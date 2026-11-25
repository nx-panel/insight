package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/addon"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/admins"
	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/alert"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"github.com/nx-panel/insight/internal/settings"
	"github.com/nx-panel/insight/internal/tunnels"
)

const manifest = `{"api":1,"slug":"insight","name":"NX Insight","version":"0.1.0","scopes":[{"scope":"telemetry:read","purpose":"x"}],"setup":"/nx/setup","health":"/health"}`

type env struct {
	t    *testing.T
	db   *gorm.DB
	srv  *httptest.Server
	http *http.Client
	det  *detect.Detector
	tw   *tunnels.Watcher
}

// tunnelPanel answers the tunnel watcher: one tunnel, healthy or not.
type tunnelPanel struct{ healthy bool }

func (p *tunnelPanel) Get(_ context.Context, path string, out any) error {
	body := `{"items":[{"id":3,"name":"to-de","tag":"tunnel-to-de","mode":"reverse","relayNodeId":1,"relayName":"ir-1","originIds":[2],"originNames":["de-1"]}]}`
	if strings.HasSuffix(path, "/status") {
		body = fmt.Sprintf(`{"healthy":%v,"relay":{"nodeId":1,"reachable":true,"sessions":[]},"origins":[]}`, p.healthy)
	}
	return json.Unmarshal([]byte(body), out)
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith is newEnv with an ingest whose shapes the server reads; its
// DB is set to the env's.
func newEnvWith(t *testing.T, in *ingest.Ingest) *env {
	t.Helper()
	dir := t.TempDir()
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(dir, "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admins.EnsureFirst(gdb, "admin", "admin-secret-1"); err != nil {
		t.Fatal(err)
	}
	a, err := addon.New(addon.Config{Manifest: []byte(manifest), DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	asns, _ := netinfo.ReadASN(strings.NewReader("5.160.0.0\t5.160.255.255\t44244\tIR\tMCI\n"))
	net := &netinfo.DB{}
	net.SetASN(asns)
	det := &detect.Detector{DB: gdb}
	tw := &tunnels.Watcher{DB: gdb}
	tg := &alert.Live{}
	live := &settings.Live{DB: gdb, Install: settings.Values{Language: "en"}, Applied: func(v settings.Values) error {
		return tg.Set(v.TelegramToken, v.TelegramChat, v.TelegramProxy, v.TelegramAPI, v.Language)
	}}
	if err := live.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if in != nil {
		in.DB = gdb
	}
	s := New(gdb, a, config.Config{}, "0.1.0", nil, Parts{Ingest: in, Detect: det, Net: net, Tunnels: tw, Settings: live, Alerts: tg})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{t: t, db: gdb, srv: srv, http: &http.Client{Jar: jar}, det: det, tw: tw}
}

func (e *env) call(method, path string, body, out any) int {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.srv.URL)
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// TestTheAdminWebNeedsASignIn: every data route is refused without a
// session and answered with one.
func TestTheAdminWebNeedsASignIn(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/status", "/api/matrix", "/api/nodes", "/api/alerts", "/api/suggestions", "/api/endpoints", "/api/ai", "/api/ai/reports", "/api/settings"} {
		if code := e.call("GET", p, nil, nil); code != http.StatusUnauthorized {
			t.Errorf("signed out GET %s = %d", p, code)
		}
	}
	if code := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong-one-1"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password = %d", code)
	}
	if code := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil); code != http.StatusOK {
		t.Fatalf("sign in = %d", code)
	}
	for _, p := range []string{"/api/status", "/api/matrix", "/api/nodes", "/api/alerts", "/api/suggestions", "/api/endpoints", "/api/ai", "/api/ai/reports", "/api/settings"} {
		if code := e.call("GET", p, nil, nil); code != http.StatusOK {
			t.Errorf("signed in GET %s = %d", p, code)
		}
	}
}

// TestTheMatrixAndTheNodes: the matrix sums the window's cells per client
// network, node and inbound with the ASN's name and the RTT; an override is
// saved and read back through the effective network.
func TestTheMatrixAndTheNodes(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	hour := time.Now().Truncate(time.Hour).Unix()
	for _, region := range []string{"Tehran", "Isfahan"} {
		row := model.PathHour{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: "vless", ClientASN: 44244, Country: "IR", Region: region, Network: "tcp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 10, Authed: 9, FailedAuth: 1, RTTSum: 150 * 9, RTTN: 9},
		}
		e.db.Create(&row)
	}
	e.db.Create(&model.NodeNetinfo{NodeID: 1, Name: "fsn", Address: "88.198.1.1", ASN: 24940, Org: "HETZNER", Country: "DE", City: "Falkenstein"})
	var m struct {
		Cells []cellView `json:"cells"`
		Nodes []nodeView `json:"nodes"`
	}
	if code := e.call("GET", "/api/matrix?hours=6", nil, &m); code != http.StatusOK {
		t.Fatalf("matrix = %d", code)
	}
	if len(m.Cells) != 1 || m.Cells[0].Accepted != 20 || m.Cells[0].Org != "MCI" || m.Cells[0].RTTMs != 150 || len(m.Nodes) != 1 {
		t.Fatalf("matrix = %+v", m)
	}
	if code := e.call("GET", "/api/matrix?hours=6&by=region", nil, &m); code != http.StatusOK || len(m.Cells) != 2 {
		t.Fatalf("by region = %d %+v", code, m.Cells)
	}
	if code := e.call("GET", "/api/matrix?hours=999", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("a window past a week = %d", code)
	}
	var n nodeView
	if code := e.call("PUT", "/api/nodes/1/override", map[string]any{"asn": 0, "org": "", "country": "de", "city": "Nuremberg"}, &n); code != http.StatusOK {
		t.Fatalf("override = %d", code)
	}
	if n.Effective.City != "Nuremberg" || n.Effective.Country != "DE" || n.Effective.Org != "HETZNER" {
		t.Fatalf("effective = %+v", n.Effective)
	}
	if code := e.call("PUT", "/api/nodes/1/override", map[string]any{"country": "DEU"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a three-letter country = %d", code)
	}
	if code := e.call("PUT", "/api/nodes/9/override", map[string]any{"city": "x"}, nil); code != http.StatusNotFound {
		t.Fatalf("an unknown node = %d", code)
	}
}

// shapesPanel answers a poll with no samples and the nodes' shapes.
type shapesPanel []ingest.NodeState

func (p shapesPanel) Get(_ context.Context, _ string, out any) error {
	raw, err := json.Marshal(map[string]any{"active": true, "nodes": p})
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// TestOnlyAWireGuardCellIsServedAsHandshakes: a WireGuard endpoint's cell
// is served with kind "endpoint" (handshakes only); an OpenVPN endpoint's,
// which counts accepted and failed like an inbound's, is served as an
// inbound's, so a cell with ninety failures in a hundred reads as one.
func TestOnlyAWireGuardCellIsServedAsHandshakes(t *testing.T) {
	in := &ingest.Ingest{Panel: func() ingest.Getter {
		return shapesPanel{{ID: 1, State: ingest.StateNodeOn, Inbounds: []ingest.Shape{
			{Tag: "wg", Kind: ingest.KindEndpoint, Type: "wireguard"},
			{Tag: "ovpn", Kind: ingest.KindEndpoint, Type: "openvpn-server"},
		}}}
	}}
	e := newEnvWith(t, in)
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	hour := time.Now().Truncate(time.Hour).Unix()
	cell := func(inbound string, c model.PathCounters) {
		e.db.Create(&model.PathHour{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: inbound, ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"},
			PathCounters: c,
		})
	}
	cell("wg", model.PathCounters{Authed: 10})
	cell("ovpn", model.PathCounters{Accepted: 100, Authed: 10, FailedAuth: 90})
	var m struct {
		Cells []cellView `json:"cells"`
	}
	if code := e.call("GET", "/api/matrix?hours=6", nil, &m); code != http.StatusOK || len(m.Cells) != 2 {
		t.Fatalf("matrix = %d %+v", code, m.Cells)
	}
	kinds := map[string]string{}
	for _, c := range m.Cells {
		kinds[c.Inbound] = c.Kind
	}
	if kinds["wg"] != ingest.KindEndpoint || kinds["ovpn"] != "" {
		t.Fatalf("kinds = %v, want wg an endpoint and ovpn an inbound", kinds)
	}
}

// TestTheNodesShowTheirTunnels: each node lists
// the tunnels it is the relay or an origin of, with the watcher's state and
// its links' last 24 hours, and the status names a tunnel that is down.
func TestTheNodesShowTheirTunnels(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	fp := &tunnelPanel{}
	e.tw.Panel = func() tunnels.Getter { return fp }
	for range 2 {
		if err := e.tw.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	e.db.Create(&model.NodeNetinfo{NodeID: 1, Name: "ir-1"})
	e.db.Create(&model.NodeNetinfo{NodeID: 2, Name: "de-1"})
	e.db.Create(&model.TunnelHour{
		TunnelCell:     model.TunnelCell{Hour: time.Now().Truncate(time.Hour).Unix(), NodeID: 2, Tunnel: "tunnel-to-de", Peer: "ir-1", Server: "192.0.2.1:443", Side: "dial"},
		TunnelCounters: model.TunnelCounters{Attempts: 40, FailedDial: 30, FailedTimeout: 8, Up: 2},
	})
	var rows []nodeRow
	if code := e.call("GET", "/api/nodes", nil, &rows); code != http.StatusOK || len(rows) != 2 {
		t.Fatalf("nodes = %d %+v", code, rows)
	}
	relay, origin := rows[0].Tunnels, rows[1].Tunnels
	if len(relay) != 1 || relay[0].Role != "relay" || relay[0].State != tunnels.Down || relay[0].Name != "to-de" {
		t.Fatalf("relay's tunnels = %+v", relay)
	}
	if len(origin) != 1 || origin[0].Role != "origin" || origin[0].Hours.Attempts != 40 || origin[0].Hours.Failed != 38 {
		t.Fatalf("origin's tunnels = %+v", origin)
	}
	var st statusView
	e.call("GET", "/api/status", nil, &st)
	if len(st.TunnelsDown) != 1 || st.TunnelsDown[0] != "to-de" || st.Tunnels.State != tunnels.StateOK {
		t.Fatalf("status = %+v / %+v", st.TunnelsDown, st.Tunnels)
	}
}

// TestAlertsNewestFirst: the list is newest first and pages by id.
func TestAlertsNewestFirst(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	for i := range 3 {
		e.db.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, ASN: 44244, At: int64(1000 + i)})
	}
	var got []struct {
		ID  uint   `json:"id"`
		Org string `json:"org"`
	}
	e.call("GET", "/api/alerts", nil, &got)
	if len(got) != 3 || got[0].ID != 3 || got[0].Org != "MCI" {
		t.Fatalf("alerts = %+v", got)
	}
	e.call("GET", "/api/alerts?before=2", nil, &got)
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("before 2 = %+v", got)
	}
}

// TestEndpointsMostSuspectFirst: the endpoints come most suspect first, and
// a probed endpoint whose path then degraded reads as followed.
func TestEndpointsMostSuspectFirst(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	at := time.Now().Add(-time.Hour).Unix()
	e.db.Create(&detect.Suspicion{NodeID: 1, Inbound: "ss", Score: 20, FollowUpFail: 30})
	e.db.Create(&detect.Suspicion{NodeID: 1, Inbound: "vless-reality", Score: 60, Replayed: 3, Probed: true, ProbedAtUnix: at})
	e.db.Create(&detect.Alert{Kind: detect.KindProbed, NodeID: 1, Inbound: "vless-reality", At: at})
	var got []endpointView
	e.call("GET", "/api/endpoints", nil, &got)
	if len(got) != 2 || got[0].Inbound != "vless-reality" || got[0].Followed != nil || got[1].Followed != nil {
		t.Fatalf("endpoints = %+v", got)
	}
	e.db.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless-reality", ASN: 44244, At: at + 600})
	e.call("GET", "/api/endpoints", nil, &got)
	if got[0].Followed == nil || !*got[0].Followed {
		t.Fatalf("followed = %v", got[0].Followed)
	}
}

// TestAISettingsKeepTheKeyServerSide: the key is saved, never sent back,
// kept when the form leaves it empty and removed only on clearKey; a bad
// setting is refused with its code; a pass cannot start while it is off.
func TestAISettingsKeepTheKeyServerSide(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	var v map[string]any
	if code := e.call("PUT", "/api/ai", map[string]any{"enabled": true, "url": "https://api.example.com/v1", "model": "m", "key": "sk-secret", "dailyTokens": 50000}, &v); code != http.StatusOK {
		t.Fatalf("put = %d %v", code, v)
	}
	if v["keySet"] != true || v["key"] != nil {
		t.Fatalf("view = %v", v)
	}
	e.call("PUT", "/api/ai", map[string]any{"enabled": false, "url": "https://api.example.com/v1", "model": "m2", "dailyTokens": 50000}, &v)
	s, _ := ai.Load(t.Context(), e.db)
	if s.Key != "sk-secret" || s.Model != "m2" {
		t.Fatalf("an empty key replaced the saved one: %+v", s)
	}
	// Through a proxy with a password: shown masked, and saved back as
	// shown without losing the password or the key.
	proxy := "socks5://u:p!ss*@127.0.0.1:1080"
	e.call("PUT", "/api/ai", map[string]any{"url": "https://api.example.com/v1", "model": "m2", "key": "sk-secret", "proxy": proxy, "dailyTokens": 50000}, &v)
	if v["proxy"] != "socks5://u:********@127.0.0.1:1080" {
		t.Fatalf("proxy shown as %v", v["proxy"])
	}
	e.call("PUT", "/api/ai", map[string]any{"url": "https://api.example.com/v1", "model": "m3", "proxy": v["proxy"], "dailyTokens": 50000}, &v)
	if s, _ := ai.Load(t.Context(), e.db); s.Key != "sk-secret" || s.Proxy != proxy || s.Model != "m3" {
		t.Fatalf("saving the form as shown changed the key or the proxy: %+v", s)
	}
	// Another host without the key typed again: the saved key does not go
	// with it.
	e.call("PUT", "/api/ai", map[string]any{"url": "https://elsewhere.example.net/v1", "model": "m3", "proxy": v["proxy"], "dailyTokens": 50000}, &v)
	if s, _ := ai.Load(t.Context(), e.db); s.Key != "" || v["keySet"] != false {
		t.Fatalf("the key followed the address to another host: %+v", s)
	}
	e.call("PUT", "/api/ai", map[string]any{"url": "https://api.example.com/v1", "model": "m2", "key": "sk-secret", "dailyTokens": 50000}, &v)
	var bad map[string]any
	if code := e.call("PUT", "/api/ai", map[string]any{"enabled": true, "url": "", "model": ""}, &bad); code != http.StatusBadRequest || bad["code"] != "ai_needs" {
		t.Fatalf("enabled with nothing = %d %v", code, bad)
	}
	if code := e.call("POST", "/api/ai/run", map[string]string{"country": "IR"}, &bad); code != http.StatusBadRequest {
		t.Fatalf("a country not configured = %d", code)
	}
	e.call("PUT", "/api/ai", map[string]any{"url": "http://127.0.0.1:11434/v1", "model": "qwen", "clearKey": true}, &v)
	if s, _ := ai.Load(t.Context(), e.db); s.Key != "" || v["keySet"] != false {
		t.Fatalf("clearKey kept %q", s.Key)
	}
	e.db.Create(&ai.Report{
		Country: "IR", Trigger: ai.TriggerDaily, At: 1, Status: ai.StatusOK,
		Findings: `[{"code":"asn_outage","severity":"critical","asn":44244}]`,
	})
	var reports struct {
		Reports []ai.Report       `json:"reports"`
		Orgs    map[string]string `json:"orgs"`
	}
	if code := e.call("GET", "/api/ai/reports?country=IR", nil, &reports); code != http.StatusOK || len(reports.Reports) != 1 || reports.Orgs["44244"] != "MCI" {
		t.Fatalf("reports = %d %+v", code, reports)
	}
}

// TestTheGateLetsOneActionThroughPerWindow: the first action goes through,
// a second within the window does not, one after it does.
func TestTheGateLetsOneActionThroughPerWindow(t *testing.T) {
	var g gate
	t0 := time.Unix(1_700_000_000, 0)
	if !g.allowAt(t0, time.Minute) {
		t.Fatal("the first action was refused")
	}
	if g.allowAt(t0.Add(59*time.Second), time.Minute) {
		t.Fatal("a second action within the window went through")
	}
	if !g.allowAt(t0.Add(time.Minute), time.Minute) {
		t.Fatal("an action after the window was refused")
	}
}
