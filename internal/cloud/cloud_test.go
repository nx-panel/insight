package cloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "insight.db")})
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

var hour = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC).Unix()

type fakeState struct {
	degraded map[detect.Key]bool
	outages  map[uint32]bool
}

func (f fakeState) Degraded() map[detect.Key]bool { return f.degraded }
func (f fakeState) Outages() map[uint32]bool      { return f.outages }

// fleet writes an hour of cells: node 1 (Hetzner, DE) serves vless-reality
// and trojan-ws to MCI and TCI; node 2 (OVH, FR) serves vless-reality; node
// 3 is a relay; an ASN-0 cell and a cell of a deleted inbound too.
func fleet(t *testing.T, gdb *gorm.DB) Sources {
	t.Helper()
	cell := func(node uint, inbound string, asn uint32, acc, authed uint64) model.PathHour {
		return model.PathHour{Hour: hour, PathCell: model.PathCell{
			NodeID: node, Inbound: inbound, ClientASN: asn, Country: "IR", Region: "Tehran", Network: "tcp", SourceKind: "peer",
		}, PathCounters: model.PathCounters{Accepted: acc, Authed: authed, FailedTLS: acc - authed, RTTSum: authed * 100, RTTN: authed}}
	}
	rows := []model.PathHour{
		cell(1, "vless-reality-sni-www.example.com", 197207, 100, 95),
		cell(1, "trojan-ws", 197207, 50, 2),
		cell(1, "vless-reality-sni-www.example.com", 58224, 80, 1),
		cell(1, "trojan-ws", 58224, 40, 1),
		cell(2, "vless-reality-sni-www.example.com", 197207, 60, 58),
		cell(2, "vless-reality-sni-www.example.com", 44244, 30, 0),
		cell(3, "relay-in", 197207, 20, 0),
		cell(2, "deleted-inbound", 197207, 10, 9),
		cell(2, "vless-reality-sni-www.example.com", model.OtherASN, 10, 9),
	}
	if err := gdb.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&model.PathSigHour{Hour: hour, PathCell: rows[1].PathCell, Sig: "tls/0/0", N: 48}).Error; err != nil {
		t.Fatal(err)
	}
	nets := []model.NodeNetinfo{
		{NodeID: 1, Name: "hetzner-1", Address: "203.0.113.10", ASN: 24940, Org: "HETZNER-AS", Country: "DE"},
		{NodeID: 2, Name: "ovh-2", Address: "198.51.100.20", ASN: 16276, Org: "OVH", Country: "FR"},
		{NodeID: 3, Name: "relay-3", Address: "192.0.2.30", ASN: 12880, Org: "DCI", Country: "IR"},
	}
	if err := gdb.Create(&nets).Error; err != nil {
		t.Fatal(err)
	}
	shapes := map[uint]map[string]ingest.Shape{
		1: {
			"vless-reality-sni-www.example.com": {Tag: "vless-reality-sni-www.example.com", Type: "vless", Transport: "none", Security: "reality"},
			"trojan-ws":                         {Tag: "trojan-ws", Type: "trojan", Transport: "ws", Security: "tls", Fronted: true},
		},
		2: {"vless-reality-sni-www.example.com": {Tag: "vless-reality-sni-www.example.com", Type: "vless", Transport: "none", Security: "reality"}},
		3: {"relay-in": {Tag: "relay-in", Type: "VLESS", Transport: "tcp", Security: "tls"}},
	}
	state := fakeState{
		degraded: map[detect.Key]bool{
			{Node: 1, Inbound: "vless-reality-sni-www.example.com", ASN: 197207, Network: "tcp"}: true,
			{Node: 1, Inbound: "trojan-ws", ASN: 197207, Network: "tcp"}:                         true,
			{Node: 1, Inbound: "vless-reality-sni-www.example.com", ASN: 58224, Network: "tcp"}:  true,
			{Node: 1, Inbound: "trojan-ws", ASN: 58224, Network: "tcp"}:                          true,
		},
		outages: map[uint32]bool{44244: true},
	}
	return Sources{
		DB: gdb, State: state, Version: "0.0.2",
		Shapes:  func() map[uint]map[string]ingest.Shape { return shapes },
		Tunnels: func() []tunnels.View { return []tunnels.View{{RelayID: 3, State: tunnels.Down}} },
		Org: func(asn uint32) string {
			return map[uint32]string{197207: "MCCI", 58224: "TCI", 44244: "IRANCELL"}[asn]
		},
	}
}

// TestABatchIsTheGlobalKeyAndNothingOfTheOperator: cells by the global
// key with a verdict,
// and no node's address, name or id, no inbound tag, no SNI.
func TestABatchIsTheGlobalKeyAndNothingOfTheOperator(t *testing.T) {
	gdb := openDB(t)
	src := fleet(t, gdb)
	b, err := Build(t.Context(), src, hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	for _, s := range []string{"example.com", "hetzner-1", "ovh-2", "relay-3", "203.0.113", "198.51.100", "192.0.2", "trojan-ws", "relay-in", "node_id", "inbound"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("the batch carries %q: %s", s, raw)
		}
	}
	if len(b.Cells) != 7 {
		t.Fatalf("cells = %d, want 7 (ASN 0 and the deleted inbound left out): %+v", len(b.Cells), b.Cells)
	}
	// Node 1 is degraded on both its inbounds for two networks: its address.
	var nodeBlocked, outage, tunnel, ok int
	for _, c := range b.Cells {
		switch c.Verdict {
		case VerdictNodeDown:
			nodeBlocked++
			if c.NodeASN != 24940 || c.NodeCC != "DE" || c.NodeOrg != "HETZNER-AS" {
				t.Errorf("node-blocked cell %+v is not node 1's host", c)
			}
		case VerdictOutage:
			outage++
			if c.ASN != 44244 || c.Org != "IRANCELL" {
				t.Errorf("outage cell %+v", c)
			}
		case VerdictTunnelDown:
			tunnel++
			if c.Proto != "vless" || c.Security != "tls" {
				t.Errorf("the relay's cell %+v: the type is lower-cased", c)
			}
		case VerdictOK:
			ok++
		}
		if c.Proto == "trojan" && c.ASN == 197207 {
			if c.Front != "cdn" || c.Transport != "ws" || c.Sigs["tls/0/0"] != 48 || c.Failed["tls"] != 48 {
				t.Errorf("trojan cell %+v", c)
			}
		}
	}
	if nodeBlocked != 4 || outage != 1 || tunnel != 1 || ok != 1 {
		t.Errorf("verdicts: node %d, outage %d, tunnel %d, ok %d", nodeBlocked, outage, tunnel, ok)
	}
}

type fakePanel struct {
	mu      sync.Mutex
	key     map[string]string
	deleted bool
	fail    bool
}

func (p *fakePanel) Put(_ context.Context, path string, body any, _ any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return &panel.Error{Status: 502, Message: "down"}
	}
	if path != "/telemetry/contributor-key" {
		return &panel.Error{Status: 404}
	}
	p.key = body.(map[string]string)
	return nil
}

func (p *fakePanel) Delete(_ context.Context, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deleted, p.key = true, nil
	return nil
}

// fakeCloud checks what Insight sends as the Worker does and answers as told.
type fakeCloud struct {
	mu       sync.Mutex
	status   int
	batches  []Batch
	feed     ed25519.PrivateKey
	report   string
	reported int64
	asked    []int64
}

func (f *fakeCloud) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pub, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-NX-Key"))
		sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-NX-Signature"))
		ctxs := map[string]string{"/v1/batch": BatchContext, "/v1/report": ReportRequestContext}
		if len(pub) != 32 || !ed25519.Verify(pub, append([]byte(ctxs[r.URL.Path]), body...), sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.status != 0 {
			w.WriteHeader(f.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "not_registered"})
			return
		}
		switch r.URL.Path {
		case "/v1/batch":
			zr, err := gzip.NewReader(bytes.NewReader(body))
			if err != nil || r.Header.Get("Content-Encoding") != "gzip" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			var b Batch
			_ = json.NewDecoder(zr).Decode(&b)
			f.batches = append(f.batches, b)
			w.WriteHeader(http.StatusAccepted)
		case "/v1/report":
			var req struct{ Since, Ts int64 }
			_ = json.Unmarshal(body, &req)
			f.asked = append(f.asked, req.Since)
			if f.report == "" || f.reported <= req.Since {
				_ = json.NewEncoder(w).Encode(map[string]any{"new": false, "extracted_at": f.reported})
				return
			}
			s := ed25519.Sign(f.feed, append([]byte(ReportContext), f.report...))
			_ = json.NewEncoder(w).Encode(map[string]any{"new": true, "extracted_at": f.reported, "tier": "full", "payload": f.report, "sig": base64.StdEncoding.EncodeToString(s)})
		}
	})
}

func setup(t *testing.T) (*Cloud, *fakePanel, *fakeCloud, *time.Time) {
	t.Helper()
	gdb := openDB(t)
	src := fleet(t, gdb)
	fc := &fakeCloud{}
	srv := httptest.NewServer(fc.handler(t))
	t.Cleanup(srv.Close)
	fp := &fakePanel{}
	now := time.Unix(hour+3600+7*60, 0) // the hour after, past its last flush
	c := &Cloud{DB: gdb, Sources: src, URL: srv.URL, Panel: func() Panel { return fp }, Now: func() time.Time { return now }}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fc.feed = priv
	c.SetFeedKey(pub)
	return c, fp, fc, &now
}

// TestModeBRegistersSendsAndStops: turning Mode B on registers the key
// with a proof the panel can check; the closed hour goes out signed; turning
// it off removes the key and drops what waits.
func TestModeBRegistersSendsAndStops(t *testing.T) {
	c, fp, fc, now := setup(t)
	ctx := t.Context()
	// Off: nothing is built or sent.
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	// On just after the hour closed: the consent starts with the hour in
	// progress, so pretend it was given an hour earlier.
	*now = time.Unix(hour+60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	pub, _ := base64.StdEncoding.DecodeString(fp.key["public_key"])
	proof, _ := base64.StdEncoding.DecodeString(fp.key["proof"])
	if !ed25519.Verify(pub, []byte(ProofContext+fp.key["public_key"]), proof) {
		t.Fatal("the proof the panel got does not verify")
	}
	*now = time.Unix(hour+3600+7*60, 0)
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fc.batches) != 1 || fc.batches[0].Hour != hour || len(fc.batches[0].Cells) != 7 {
		t.Fatalf("the cloud got %+v", fc.batches)
	}
	st, _ := c.Status(ctx)
	if !st.On || !st.Registered || st.LastSent == nil || st.LastSent.Hour != hour || st.Pending != 0 {
		t.Fatalf("status = %+v", st)
	}
	// A second tick sends nothing again.
	_ = c.Tick(ctx)
	if len(fc.batches) != 1 {
		t.Fatalf("sent %d times", len(fc.batches))
	}

	// A key the licence service does not know yet waits and is retried.
	fc.status = 403
	*now = now.Add(time.Hour)
	if err := c.DB.Create(&model.PathHour{Hour: hour + 3600, PathCell: model.PathCell{NodeID: 2, Inbound: "vless-reality-sni-www.example.com", ClientASN: 197207, Country: "IR", Network: "tcp"}, PathCounters: model.PathCounters{Accepted: 5, Authed: 5}}).Error; err != nil {
		t.Fatal(err)
	}
	_ = c.Tick(ctx)
	st, _ = c.Status(ctx)
	if st.Pending != 1 || !strings.Contains(st.Error, "403") {
		t.Fatalf("after a 403: %+v", st)
	}
	fc.status = 0
	*now = now.Add(10 * time.Minute)
	_ = c.Tick(ctx)
	if len(fc.batches) != 2 {
		t.Fatalf("the waiting batch was not retried: %d", len(fc.batches))
	}

	// Off: the key leaves the panel and nothing more is sent.
	fc.status = 503
	*now = now.Add(time.Hour)
	if err := c.DB.Create(&model.PathHour{Hour: hour + 7200, PathCell: model.PathCell{NodeID: 2, Inbound: "vless-reality-sni-www.example.com", ClientASN: 197207, Country: "IR", Network: "tcp"}, PathCounters: model.PathCounters{Accepted: 5, Authed: 5}}).Error; err != nil {
		t.Fatal(err)
	}
	_ = c.Tick(ctx)
	if err := c.SetOn(ctx, false); err != nil {
		t.Fatal(err)
	}
	if !fp.deleted {
		t.Error("the key was not removed from the panel")
	}
	var waiting int64
	c.DB.Model(&Outbox{}).Where("sent_at = 0").Count(&waiting)
	if waiting != 0 {
		t.Errorf("%d batches still wait after Mode B was turned off", waiting)
	}
	fc.status = 0
	_ = c.Tick(ctx)
	if len(fc.batches) != 2 {
		t.Error("a batch went out with Mode B off")
	}
}

// TestTheReportComesOnceAndIsChecked: Insight sends the extraction time of
// the report it holds; a newer one is kept only when NX's signature
// verifies, and an answer of none keeps it.
func TestTheReportComesOnceAndIsChecked(t *testing.T) {
	c, _, fc, _ := setup(t)
	ctx := t.Context()
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckReport(ctx, true); err != nil {
		t.Fatal(err)
	}
	if h := c.Held(ctx); h.Report != nil {
		t.Fatalf("a report before any was published: %+v", h)
	}
	fc.reported = hour + 7200
	fc.report = `{"v":1,"extracted_at":` + itoa(hour+7200) + `,"tier":"full","countries":[{"cc":"IR","from":1,"to":2,"contributors":"5-9","findings":[{"code":"strategy_works","severity":"info","asn":197207,"org":"MCCI","strategy":"vless/none/reality/direct","node_asn":0,"confidence":0.9}]}]}`
	if err := c.CheckReport(ctx, true); err != nil {
		t.Fatal(err)
	}
	h := c.Held(ctx)
	if h.Report == nil || h.Report.ExtractedAt != hour+7200 || h.Report.Countries[0].Findings[0].Code != "strategy_works" {
		t.Fatalf("held = %+v", h)
	}
	if err := c.CheckReport(ctx, true); err != nil {
		t.Fatal(err)
	}
	if fc.asked[len(fc.asked)-1] != hour+7200 {
		t.Fatalf("Insight asked since %d, want the report it holds", fc.asked[len(fc.asked)-1])
	}
	if c.Held(ctx).Report == nil {
		t.Fatal("the no-new answer dropped the report held")
	}
	// A report signed by anyone but NX is refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	fc.feed = other
	fc.reported++
	if err := c.CheckReport(ctx, true); err == nil {
		t.Fatal("a report with a foreign signature was taken")
	}
	if c.Held(ctx).Report.ExtractedAt != hour+7200 {
		t.Fatal("the held report was replaced")
	}
	// The gap: an opening of the page within ReportGap asks nothing.
	n := len(fc.asked)
	_ = c.CheckReport(ctx, false)
	if len(fc.asked) != n {
		t.Error("a check within the gap went out")
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
