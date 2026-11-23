package ai_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

// openDB is a fresh SQLite database, or the PostgreSQL one
// NX_INSIGHT_PG_DSN names, emptied.
func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")}
	if dsn := os.Getenv("NX_INSIGHT_PG_DSN"); dsn != "" {
		cfg = config.Config{Driver: config.DriverPostgres, DSN: dsn}
	}
	gdb, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Driver == config.DriverPostgres {
		for _, m := range append(append(model.All(), detect.Tables()...), ai.Tables()...) {
			gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m)
		}
	}
	return gdb
}

type state struct{}

func (state) Degraded() map[detect.Key]bool {
	return map[detect.Key]bool{{Node: 1, Inbound: "vless-reality", ASN: 44244, Network: "tcp"}: true}
}
func (state) Outages() map[uint32]bool { return map[uint32]bool{} }

var now = time.Date(2026, 11, 23, 12, 30, 0, 0, time.UTC)

// seed is two client networks on two nodes: MCI blocked on node 1's
// REALITY and fine on node 2, TCI fine everywhere; and one row of another
// country, which must not be sent.
func seed(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	hour := now.Truncate(time.Hour).Unix()
	rows := []model.PathHour{
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: "vless-reality", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 400, Authed: 40, FailedTLS: 360},
		},
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 2, Inbound: "vless-reality", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 300, Authed: 290, RTTSum: 120 * 290, RTTN: 290},
		},
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: "hy2", ClientASN: 58224, Country: "IR", Network: "udp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 100, Authed: 98},
		},
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 2, Inbound: "vless-reality", ClientASN: 12389, Country: "RU", Network: "tcp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 100, Authed: 99},
		},
	}
	for i := range rows {
		if err := gdb.Create(&rows[i]).Error; err != nil {
			t.Fatal(err)
		}
	}
	gdb.Create(&model.NodeNetinfo{NodeID: 1, Name: "fsn-secret-name", Address: "88.198.1.1", ASN: 24940, Org: "HETZNER", Country: "DE"})
	gdb.Create(&model.NodeNetinfo{NodeID: 2, Name: "ams", Address: "5.6.7.8", ASN: 14061, Org: "DIGITALOCEAN", Country: "NL"})
}

// provider is a fake OpenAI-compatible API.
type provider struct {
	mu       sync.Mutex
	bodies   []string
	auth     []string
	answer   string
	status   int
	noSchema bool // refuse json_schema like a provider without it
}

func (p *provider) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		p.mu.Lock()
		defer p.mu.Unlock()
		p.bodies = append(p.bodies, string(raw))
		p.auth = append(p.auth, r.Header.Get("Authorization"))
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		if p.noSchema && strings.Contains(string(raw), `"json_schema"`) {
			http.Error(w, `{"error":{"message":"response_format json_schema is not supported"}}`, http.StatusBadRequest)
			return
		}
		if p.status != 0 {
			http.Error(w, "overloaded", p.status)
			return
		}
		content, _ := json.Marshal(p.answer)
		_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":`+string(content)+`}}],"usage":{"total_tokens":1500}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const goodAnswer = `{"findings":[
 {"code":"inbound_blocked","severity":"critical","asn":44244,"node":1,"inbound":"vless-reality","to_node":0,"to_inbound":"","confidence":0.9},
 {"code":"move_users","severity":"warn","asn":44244,"node":1,"inbound":"vless-reality","to_node":2,"to_inbound":"vless-reality","confidence":0.8},
 {"code":"node_blocked","severity":"critical","asn":44244,"node":7,"inbound":"","to_node":0,"to_inbound":"","confidence":0.5},
 {"code":"invent_a_code","severity":"warn","asn":0,"node":0,"inbound":"","to_node":0,"to_inbound":"","confidence":1},
 {"code":"rotate_address","severity":"info","asn":44244,"node":1,"inbound":"x","to_node":2,"to_inbound":"y","confidence":3}
]}`

func enable(t *testing.T, gdb *gorm.DB, url string, budget int) {
	t.Helper()
	if err := ai.Save(context.Background(), gdb, ai.Settings{Enabled: true, URL: url + "/v1/", Model: "m", Key: "sk-test", DailyTokens: budget}); err != nil {
		t.Fatal(err)
	}
}

func reports(t *testing.T, gdb *gorm.DB) []ai.Report {
	t.Helper()
	var out []ai.Report
	gdb.Order("id").Find(&out)
	return out
}

// wait lets a background pass finish.
func wait(r *ai.Runner) {
	for range 200 {
		if !r.Running() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestADailyPassSendsAggregatesAndKeepsValidFindings is Mode A's core: a
// pass per country sends that country's paths as counts and ratios — no
// node address or name, no other country — and keeps only the findings that
// name what the table holds, with unused fields cleared.
func TestADailyPassSendsAggregatesAndKeepsValidFindings(t *testing.T) {
	gdb := openDB(t)
	seed(t, gdb)
	p := &provider{answer: goodAnswer}
	srv := p.server(t)
	enable(t, gdb, srv.URL, 100_000)
	r := &ai.Runner{DB: gdb, State: state{}, Org: func(a uint32) string { return map[uint32]string{44244: "MCI"}[a] }, Countries: []string{"IR", "CN"}, Now: func() time.Time { return now }}
	r.Tick(context.Background())
	wait(r)

	got := reports(t, gdb)
	if len(got) != 2 || got[0].Country != "IR" || got[0].Status != ai.StatusOK || got[0].Trigger != ai.TriggerDaily ||
		got[0].Tokens != 1500 || got[0].Rows != 3 || got[0].Dropped != 2 || got[1].Country != "CN" || got[1].Status != ai.StatusEmpty {
		t.Fatalf("reports = %+v", got)
	}
	var findings []ai.Finding
	_ = json.Unmarshal([]byte(got[0].Findings), &findings)
	if len(findings) != 3 || findings[0].Code != ai.CodeInboundBlocked || findings[1].ToNode != 2 ||
		findings[2].Code != ai.CodeRotateAddress || findings[2].ASN != 0 || findings[2].Inbound != "" || findings[2].ToNode != 0 || findings[2].Confidence != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if len(p.bodies) != 1 || p.auth[0] != "Bearer sk-test" {
		t.Fatalf("calls = %d, auth %v", len(p.bodies), p.auth)
	}
	body := p.bodies[0]
	for _, leak := range []string{"88.198.1.1", "5.6.7.8", "fsn-secret-name", "12389", "5.160."} {
		if strings.Contains(body, leak) {
			t.Errorf("the request carries %q", leak)
		}
	}
	for _, want := range []string{"44244|MCI|1|vless-reality|tcp|400|10|90|", "degraded", "1|DE|HETZNER", `"json_schema"`, `"strict":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("the request lacks %q:\n%s", want, body)
		}
	}

	// Within the day, with no alert, nothing more is sent.
	r.Tick(context.Background())
	wait(r)
	if len(p.bodies) != 1 {
		t.Fatalf("a second pass within the day: %d calls", len(p.bodies))
	}
}

// TestAnAlertTriggersAPassAfterTheGap: an alert on a network seen in the
// country triggers another pass once AnomalyGap has passed, not before.
func TestAnAlertTriggersAPassAfterTheGap(t *testing.T) {
	gdb := openDB(t)
	seed(t, gdb)
	p := &provider{answer: `{"findings":[{"code":"all_clear","severity":"info","asn":0,"node":0,"inbound":"","to_node":0,"to_inbound":"","confidence":1}]}`}
	srv := p.server(t)
	enable(t, gdb, srv.URL, 100_000)
	clock := now
	r := &ai.Runner{DB: gdb, State: state{}, Countries: []string{"IR"}, Now: func() time.Time { return clock }}
	r.Tick(context.Background())
	wait(r)
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless-reality", ASN: 44244, Network: "tcp", At: clock.Add(10 * time.Minute).Unix()})
	clock = clock.Add(30 * time.Minute)
	r.Tick(context.Background())
	wait(r)
	if len(p.bodies) != 1 {
		t.Fatalf("an alert inside the gap passed again: %d calls", len(p.bodies))
	}
	clock = now.Add(61 * time.Minute)
	r.Tick(context.Background())
	wait(r)
	got := reports(t, gdb)
	if len(p.bodies) != 2 || got[len(got)-1].Trigger != ai.TriggerAnomaly {
		t.Fatalf("after the gap: %d calls, %+v", len(p.bodies), got)
	}
	// An alert on a network of another country triggers nothing.
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 2, ASN: 12389, At: now.Add(70 * time.Minute).Unix()})
	clock = now.Add(3 * time.Hour)
	r.Tick(context.Background())
	wait(r)
	if len(p.bodies) != 2 {
		t.Fatalf("another country's alert passed: %d calls", len(p.bodies))
	}
}

// TestTheBudgetAndTheBreakerHoldCalls: past the day's budget no call is made
// and one budget report says so; a failing provider is retried only after
// the breaker's pause; a provider without JSON schema is asked for a plain
// JSON object instead.
func TestTheBudgetAndTheBreakerHoldCalls(t *testing.T) {
	gdb := openDB(t)
	seed(t, gdb)
	p := &provider{answer: `{"findings":[]}`, status: http.StatusServiceUnavailable}
	srv := p.server(t)
	enable(t, gdb, srv.URL, 100_000)
	clock := now
	r := &ai.Runner{DB: gdb, State: state{}, Countries: []string{"IR"}, Now: func() time.Time { return clock }}
	r.Tick(context.Background())
	wait(r)
	clock = clock.Add(5 * time.Minute)
	r.Tick(context.Background())
	wait(r)
	got := reports(t, gdb)
	if len(p.bodies) != 1 || len(got) != 1 || got[0].Status != ai.StatusError || !strings.Contains(got[0].Error, "503") {
		t.Fatalf("a failing provider: %d calls, %+v", len(p.bodies), got)
	}
	p.mu.Lock()
	p.status, p.noSchema = 0, true
	p.mu.Unlock()
	clock = clock.Add(16 * time.Minute)
	r.Tick(context.Background())
	wait(r)
	got = reports(t, gdb)
	if last := got[len(got)-1]; last.Status != ai.StatusOK || len(p.bodies) != 3 || !strings.Contains(p.bodies[2], `"json_object"`) {
		t.Fatalf("after the pause, without a schema: %+v, %d calls", last, len(p.bodies))
	}

	// The budget: what is left today is less than one table.
	gdb.Create(&ai.Report{Country: "IR", Trigger: ai.TriggerManual, At: clock.Unix(), Status: ai.StatusOK, Tokens: 99_500, Findings: "[]"})
	before := len(p.bodies)
	if !r.RunNow(context.Background(), "IR") {
		t.Fatal("run now refused")
	}
	wait(r)
	r.RunNow(context.Background(), "IR")
	wait(r)
	got = reports(t, gdb)
	budget := 0
	for _, g := range got {
		if g.Status == ai.StatusBudget {
			budget++
		}
	}
	// No call goes out, and each pass the admin asked for says why.
	if len(p.bodies) != before || budget != 2 {
		t.Fatalf("past the budget: %d new calls, %d budget reports", len(p.bodies)-before, budget)
	}
}

func TestSettingsAreChecked(t *testing.T) {
	for _, c := range []struct {
		s   ai.Settings
		err error
	}{
		{ai.Settings{Enabled: true}, ai.ErrNeeds},
		{ai.Settings{URL: "ftp://x"}, ai.ErrURL},
		{ai.Settings{URL: "http://127.0.0.1:11434/v1", Proxy: "telnet://x"}, ai.ErrProxy},
		{ai.Settings{DailyTokens: 10}, ai.ErrBudget},
		{ai.Settings{Enabled: true, URL: "http://127.0.0.1:11434/v1/", Model: "qwen2.5:7b"}, nil},
	} {
		if err := c.s.Validate(); !errors.Is(err, c.err) {
			t.Errorf("%+v: %v, want %v", c.s, err, c.err)
		}
	}
	gdb := openDB(t)
	s, err := ai.Load(context.Background(), gdb)
	if err != nil || s.Enabled || s.DailyTokens != ai.DefaultDailyTokens {
		t.Fatalf("nothing saved = %+v, %v", s, err)
	}
}

func TestParseRefusesWhatIsNotTheSchema(t *testing.T) {
	if _, _, err := ai.Parse("I think node 1 is blocked.", ai.Table{}); err == nil {
		t.Fatal("prose was taken")
	}
	got, _, err := ai.Parse("```json\n{\"findings\":[{\"code\":\"all_clear\",\"severity\":\"info\"}]}\n```", ai.Table{})
	if err != nil || len(got) != 1 {
		t.Fatalf("a fenced answer: %+v, %v", got, err)
	}
}

// TestFindingsTheNumbersContradictAreDropped: a finding that names real
// paths but says what their numbers do not — the usual failure of a small
// local model — is dropped.
func TestFindingsTheNumbersContradictAreDropped(t *testing.T) {
	tbl := ai.Table{
		Nodes: []ai.HostNode{{ID: 1}, {ID: 2}},
		Paths: []ai.Path{
			{ASN: 44244, Node: 1, Inbound: "vless-reality", Success: 10, Fail: 90, NormalFail: 3, Early: 5, NormalEarly: 4},
			{ASN: 44244, Node: 2, Inbound: "vless-reality", Success: 96, NormalFail: 3, NormalEarly: 4},
			{ASN: 44244, Node: 1, Inbound: "hy2", Success: 97, NormalFail: 2, NormalEarly: 3},
			{ASN: 58224, Node: 1, Inbound: "hy2", Success: 92, Early: 60, NormalEarly: 5},
		},
	}
	f := func(code string, asn uint32, node uint, inbound string, to uint, toIn string) string {
		raw, _ := json.Marshal(ai.Finding{Code: code, Severity: "warn", ASN: asn, Node: node, Inbound: inbound, ToNode: to, ToInbound: toIn, Confidence: 0.5})
		return string(raw)
	}
	answer := `{"findings":[` + strings.Join([]string{
		f(ai.CodeInboundBlocked, 44244, 1, "vless-reality", 0, ""),         // kept
		f(ai.CodeNodeBlocked, 44244, 1, "", 0, ""),                         // hy2 works there: dropped
		f(ai.CodeProtoBlocked, 44244, 0, "vless-reality", 0, ""),           // works on node 2: dropped
		f(ai.CodeThrottled, 58224, 1, "hy2", 0, ""),                        // kept
		f(ai.CodeMoveUsers, 44244, 1, "vless-reality", 2, "vless-reality"), // kept
		f(ai.CodeMoveUsers, 44244, 1, "hy2", 2, "vless-reality"),           // hy2 is not blocked: dropped
		f(ai.CodeRotateAddress, 0, 1, "", 0, ""),                           // no network blocked on all of node 1: dropped
		f(ai.CodeASNOutage, 44244, 0, "", 0, ""),                           // dropped
		f(ai.CodeAllClear, 0, 0, "", 0, ""),                                // a blocked path: dropped
		f(ai.CodeProbing, 0, 1, "hy2", 0, ""),                              // no probe evidence: dropped
	}, ",") + `]}`
	got, dropped, err := ai.Parse(answer, tbl)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, g := range got {
		codes = append(codes, g.Code)
	}
	if strings.Join(codes, ",") != "inbound_blocked,throttled,move_users" || dropped != 7 {
		t.Fatalf("kept %v, dropped %d", codes, dropped)
	}
}

// TestAProviderWithoutMaxTokensIsAskedAgain: a provider that refuses
// max_tokens (OpenAI's reasoning models) is asked with
// max_completion_tokens, and remembered.
func TestAProviderWithoutMaxTokensIsAskedAgain(t *testing.T) {
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(raw))
		if strings.Contains(string(raw), `"max_tokens"`) {
			http.Error(w, `{"error":{"message":"Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead."}}`, http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"{\"findings\":[]}"}}]}`)
	}))
	defer srv.Close()
	c := &ai.Client{HTTP: srv.Client()}
	s := ai.Settings{URL: srv.URL, Model: "o-mini"}
	for range 2 {
		a, err := c.Complete(context.Background(), s, "table")
		if err != nil || a.Content != `{"findings":[]}` || a.Tokens == 0 {
			t.Fatalf("answer = %+v, %v", a, err)
		}
	}
	if len(bodies) != 3 || !strings.Contains(bodies[2], `"max_completion_tokens":3000`) {
		t.Fatalf("%d requests: %v", len(bodies), bodies)
	}
}

// TestNothingIsRotatedForANetworkThatIsCutOff: with a network in an outage
// its dead paths are no block of the operator's — no node_blocked,
// inbound_blocked, rotate or move for it is kept (P20); and node_blocked
// needs another node that works for the network.
func TestNothingIsRotatedForANetworkThatIsCutOff(t *testing.T) {
	tbl := ai.Table{
		Nodes:   []ai.HostNode{{ID: 1}, {ID: 2}},
		Outages: []uint32{44244},
		Paths: []ai.Path{
			{ASN: 44244, Node: 1, Inbound: "vless", Success: 2, Degraded: true},
			{ASN: 44244, Node: 2, Inbound: "vless", Success: 1, Degraded: true},
			{ASN: 58224, Node: 1, Inbound: "vless", Success: 95},
			{ASN: 58224, Node: 2, Inbound: "vless", Success: 30},
			{ASN: 58224, Node: 2, Inbound: "vless", Network: "udp", Success: 96},
		},
	}
	f := func(code string, asn uint32, node uint, inbound string, to uint, toIn string) string {
		raw, _ := json.Marshal(ai.Finding{Code: code, Severity: "warn", ASN: asn, Node: node, Inbound: inbound, ToNode: to, ToInbound: toIn})
		return string(raw)
	}
	answer := `{"findings":[` + strings.Join([]string{
		f(ai.CodeNodeBlocked, 44244, 1, "", 0, ""),         // an outage: dropped
		f(ai.CodeInboundBlocked, 44244, 1, "vless", 0, ""), // dropped
		f(ai.CodeRotateAddress, 0, 1, "", 0, ""),           // dropped
		f(ai.CodeRotateEndpoint, 0, 1, "vless", 0, ""),     // dropped
		f(ai.CodeASNOutage, 44244, 0, "", 0, ""),           // kept
		f(ai.CodeInboundBlocked, 58224, 2, "vless", 0, ""), // its tcp side is blocked: kept
		f(ai.CodeMoveUsers, 58224, 1, "vless", 2, "vless"), // node 1 works; and node 2's tcp does not: dropped
		f(ai.CodeProtoBlocked, 58224, 0, "vless", 0, ""),   // works on node 1: dropped
	}, ",") + `]}`
	got, dropped, err := ai.Parse(answer, tbl)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, g := range got {
		codes = append(codes, g.Code)
	}
	if strings.Join(codes, ",") != "asn_outage,inbound_blocked" || dropped != 6 {
		t.Fatalf("kept %v, dropped %d", codes, dropped)
	}
}

// TestNothingIsRotatedOnARelayWhoseTunnelIsCut: with a relay's tunnel
// down, its dead paths are the tunnel (P26) — tunnel_down is kept, a block
// or rotation for that node is dropped, moving its users to a working node
// is kept; and a WireGuard endpoint's row, whose success is unknown, is
// down only by its state.
func TestNothingIsRotatedOnARelayWhoseTunnelIsCut(t *testing.T) {
	tbl := ai.Table{
		Nodes:   []ai.HostNode{{ID: 1}, {ID: 2}},
		Tunnels: []ai.TunnelRow{{Name: "to-de", Relay: 1, Origins: []uint{3}, Down: true}},
		Paths: []ai.Path{
			{ASN: 44244, Node: 1, Inbound: "vless", Success: 2, Degraded: true},
			{ASN: 44244, Node: 2, Inbound: "vless", Success: 95},
			{ASN: 44244, Node: 2, Inbound: "wg", Network: "udp", Endpoint: true, Success: -1, Fail: -1, NormalFail: -1},
		},
	}
	f := func(code string, asn uint32, node uint, inbound string, to uint, toIn string) string {
		raw, _ := json.Marshal(ai.Finding{Code: code, Severity: "warn", ASN: asn, Node: node, Inbound: inbound, ToNode: to, ToInbound: toIn})
		return string(raw)
	}
	answer := `{"findings":[` + strings.Join([]string{
		f(ai.CodeTunnelDown, 0, 1, "", 0, ""),              // kept
		f(ai.CodeTunnelDown, 0, 2, "", 0, ""),              // node 2 has no tunnel down: dropped
		f(ai.CodeNodeBlocked, 44244, 1, "", 0, ""),         // the tunnel: dropped
		f(ai.CodeRotateAddress, 0, 1, "", 0, ""),           // dropped
		f(ai.CodeInboundBlocked, 44244, 1, "vless", 0, ""), // dropped
		f(ai.CodeMoveUsers, 44244, 1, "vless", 2, "vless"), // kept
		f(ai.CodeInboundBlocked, 44244, 2, "wg", 0, ""),    // an endpoint not degraded: dropped
	}, ",") + `]}`
	got, dropped, err := ai.Parse(answer, tbl)
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for _, g := range got {
		codes = append(codes, g.Code)
	}
	if strings.Join(codes, ",") != "tunnel_down,move_users" || dropped != 5 {
		t.Fatalf("kept %v, dropped %d", codes, dropped)
	}
	text := tbl.Text()
	if !strings.Contains(text, "# tunnels: tunnel|relay_node|origin_nodes|state\nto-de|1|3|down\n") ||
		!strings.Contains(text, "|wg|udp|0|-|-|-|") || !strings.Contains(text, "|endpoint\n") {
		t.Fatalf("table:\n%s", text)
	}
}

// TestASavedKeyStaysWithItsProvider: the saved key is kept for the same API
// host and proxy only, and a proxy's password is never shown.
func TestASavedKeyStaysWithItsProvider(t *testing.T) {
	old := ai.Settings{URL: "https://api.example.com/v1", Proxy: "socks5://u:secret@127.0.0.1:1080"}
	for url, same := range map[string]bool{
		"https://api.example.com/v1":  true,
		"https://API.example.com/v2/": true,
		"http://api.example.com/v1":   false,
		"https://evil.example.net/v1": false,
	} {
		if got := (ai.Settings{URL: url, Proxy: old.Proxy}).SameProvider(old); got != same {
			t.Errorf("%s: same provider = %v, want %v", url, got, same)
		}
	}
	if (ai.Settings{URL: old.URL, Proxy: "socks5://attacker.example:1080"}).SameProvider(old) {
		t.Error("another proxy read as the same provider")
	}
	masked := ai.MaskProxy(old.Proxy)
	if masked != "socks5://u:********@127.0.0.1:1080" {
		t.Fatalf("masked = %s", masked)
	}
	// A password a URL library writes differently is still the same proxy:
	// saving the form unchanged must not drop the key.
	for _, proxy := range []string{"http://user:p!ss(1)*@proxy.example:8080", "HTTP://user:pw@proxy.example:8080"} {
		saved := ai.Settings{URL: old.URL, Proxy: proxy}
		back := ai.Settings{URL: old.URL, Proxy: ai.UnmaskProxy(ai.MaskProxy(proxy), proxy)}
		if !back.SameProvider(saved) || back.Proxy != proxy {
			t.Errorf("%s: came back as %s, same provider %v", proxy, back.Proxy, back.SameProvider(saved))
		}
	}
	if got := ai.UnmaskProxy("http://u:********@127.0.0.1:1080", old.Proxy); strings.Contains(got, "secret") {
		t.Fatalf("the password followed the proxy to another scheme: %s", got)
	}
	if got := ai.UnmaskProxy(masked, old.Proxy); got != old.Proxy {
		t.Fatalf("unmasked = %s", got)
	}
	if got := ai.UnmaskProxy(strings.Replace(masked, "127.0.0.1", "203.0.113.5", 1), old.Proxy); strings.Contains(got, "secret") {
		t.Fatalf("the password followed the proxy to another host: %s", got)
	}
	for _, bad := range []string{"https://api.example.com/v1?x=", "https://api.example.com/v1?", "https://api.example.com/v1#", "https://u:p@api.example.com/v1"} {
		s := ai.Settings{URL: bad}
		if err := s.Validate(); !errors.Is(err, ai.ErrURL) {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// TestTagsOfNoLettersDoNotSilenceTheAnalysis: two tags that clean to
// nothing (flags, symbols) are not an ambiguous spelling of the empty tag
// every inbound-less finding carries.
func TestTagsOfNoLettersDoNotSilenceTheAnalysis(t *testing.T) {
	tbl := ai.Table{
		Nodes:   []ai.HostNode{{ID: 1}, {ID: 2}},
		Outages: []uint32{44244},
		Paths: []ai.Path{
			{ASN: 44244, Node: 1, Inbound: "🇩🇪", Success: 2, Degraded: true},
			{ASN: 44244, Node: 2, Inbound: "🇳🇱", Success: 1, Degraded: true},
		},
	}
	got, dropped, err := ai.Parse(`{"findings":[{"code":"asn_outage","severity":"critical","asn":44244,"node":0,"inbound":"","to_node":0,"to_inbound":"","confidence":0.9}]}`, tbl)
	if err != nil || len(got) != 1 || dropped != 0 {
		t.Fatalf("kept %+v, dropped %d, %v", got, dropped, err)
	}
}
