package cloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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

// openDB is a fresh SQLite file, or the PostgreSQL database
// NX_INSIGHT_PG_DSN names, emptied, so the consent's checks run on both.
func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	cfg := config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "insight.db")}
	if dsn := os.Getenv("NX_INSIGHT_PG_DSN"); dsn != "" {
		cfg = config.Config{Driver: config.DriverPostgres, DSN: dsn}
	}
	gdb, err := db.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Driver == config.DriverPostgres {
		for _, m := range model.All() {
			gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m)
		}
	}
	return gdb
}

var hour = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC).Unix()

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
	src := Sources{
		DB: gdb, Version: "0.0.2",
		Shapes:  func() map[uint]map[string]ingest.Shape { return shapes },
		Tunnels: func() []tunnels.View { return []tunnels.View{{RelayID: 3, State: tunnels.Down, Judged: true}} },
		Org: func(asn uint32) string {
			return map[uint32]string{197207: "MCCI", 58224: "TCI", 44244: "IRANCELL"}[asn]
		},
	}
	// What an evaluation halfway through the hour left: node 1 degraded on
	// both its inbounds for two networks, IRANCELL out, relay 3's tunnel
	// down. Written as recorded, whether Mode B is on or not.
	r := readAt(hour+30*60, node1Paths()...)
	r.Outages[44244] = true
	if err := gdb.Create(marksAt(r, src.Tunnels(), hour)).Error; err != nil {
		t.Fatal(err)
	}
	return src
}

// fleetPaths are the paths fleet's hour holds, the folded ASN aside.
func fleetPaths() []detect.Key {
	vr := "vless-reality-sni-www.example.com"
	return []detect.Key{
		{Node: 1, Inbound: vr, ASN: 197207, Network: "tcp"},
		{Node: 1, Inbound: "trojan-ws", ASN: 197207, Network: "tcp"},
		{Node: 1, Inbound: vr, ASN: 58224, Network: "tcp"},
		{Node: 1, Inbound: "trojan-ws", ASN: 58224, Network: "tcp"},
		{Node: 2, Inbound: vr, ASN: 197207, Network: "tcp"},
		{Node: 2, Inbound: vr, ASN: 44244, Network: "tcp"},
		{Node: 3, Inbound: "relay-in", ASN: 197207, Network: "tcp"},
		{Node: 2, Inbound: "deleted-inbound", ASN: 197207, Network: "tcp"},
	}
}

// node1Paths are node 1's four paths.
func node1Paths() []detect.Key { return fleetPaths()[:4] }

// readAt is an evaluation at unix second at that judged every fleet path
// and found the given ones degraded, with no outage.
func readAt(at int64, degraded ...detect.Key) detect.Reading {
	r := detect.Reading{At: time.Unix(at, 0), Judged: map[detect.Key]bool{}, Degraded: map[detect.Key]bool{}, Outages: map[uint32]bool{}}
	for _, k := range fleetPaths() {
		r.Judged[k] = true
	}
	for _, k := range degraded {
		r.Degraded[k] = true
	}
	return r
}

// on turns Mode B on as consented before the fleet's hour: off, Mark
// records nothing.
func on(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	if err := SeedOn(t.Context(), gdb, hour-3600); err != nil {
		t.Fatal(err)
	}
}

// record marks r with the tunnels views.
func record(t *testing.T, gdb *gorm.DB, r detect.Reading, views []tunnels.View) {
	t.Helper()
	if err := mark(t.Context(), gdb, r, views); err != nil {
		t.Fatal(err)
	}
}

// cellVerdicts are a batch's verdicts by cell: client ASN, hosting ASN,
// protocol.
func cellVerdicts(b Batch) map[string]string {
	out := map[string]string{}
	for _, c := range b.Cells {
		out[fmt.Sprintf("%d/%d/%s", c.ASN, c.NodeASN, c.Proto)] = c.Verdict
	}
	return out
}

// fleetVerdicts are fleet's hour as fleet's marks give it.
func fleetVerdicts() map[string]string {
	return map[string]string{
		"197207/24940/vless": VerdictNodeDown, "197207/24940/trojan": VerdictNodeDown,
		"58224/24940/vless": VerdictNodeDown, "58224/24940/trojan": VerdictNodeDown,
		"197207/16276/vless": VerdictOK, "44244/16276/vless": VerdictOutage, "197207/12880/vless": VerdictTunnelDown,
	}
}

// with is want with the given cells changed.
func with(want map[string]string, kv ...string) map[string]string {
	for i := 0; i+1 < len(kv); i += 2 {
		want[kv[i]] = kv[i+1]
	}
	return want
}

// checkVerdicts builds hour and compares its verdicts, cell by cell.
func checkVerdicts(t *testing.T, src Sources, step string, want map[string]string) {
	t.Helper()
	b, _, err := build(t.Context(), src, hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := cellVerdicts(b); !maps.Equal(got, want) {
		t.Errorf("%s: verdicts %v, want %v", step, got, want)
	}
}

func marksIn(t *testing.T, gdb *gorm.DB, h int64) int64 {
	t.Helper()
	n, err := countMarks(gdb, h)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAnHourCarriesItsOwnVerdicts: a batch's verdicts are what was read
// during its hour, up to its last second and not after, never what is
// read when it is built.
func TestAnHourCarriesItsOwnVerdicts(t *testing.T) {
	gdb := openDB(t)
	src := fleet(t, gdb)
	on(t, gdb)
	// Everything recovered by the time the hour is built.
	record(t, gdb, readAt(hour+3600+3*60), nil)
	checkVerdicts(t, src, "recovered at build time", fleetVerdicts())

	// A path read bad from the next hour's first second on says nothing of
	// this one; read in its last second, it does.
	node2 := fleetPaths()[4]
	r := readAt(hour+3600, node2)
	record(t, gdb, r, nil)
	checkVerdicts(t, src, "degraded in the next hour", fleetVerdicts())
	r.At = time.Unix(hour+3599, 0)
	record(t, gdb, r, nil)
	checkVerdicts(t, src, "degraded in its last second", with(fleetVerdicts(), "197207/16276/vless", VerdictDegraded))
}

// TestANodeIsBlockedAtOneRead: a node's address reads as blocked only when
// one read finds most of its judged paths degraded; two halves at two
// moments are two strategy problems, not a block. A judged path counts with
// no traffic at all, as a dead address leaves it.
func TestANodeIsBlockedAtOneRead(t *testing.T) {
	gdb := openDB(t)
	src := fleet(t, gdb)
	on(t, gdb)
	// fleet's own marks block node 1; this test starts from none.
	if err := gdb.Where("1 = 1").Delete(&model.HourMark{}).Error; err != nil {
		t.Fatal(err)
	}
	p := node1Paths()
	record(t, gdb, readAt(hour+20*60, p[0], p[3]), nil)
	record(t, gdb, readAt(hour+45*60, p[1], p[2]), nil)
	degraded := map[string]string{
		"197207/24940/vless": VerdictDegraded, "197207/24940/trojan": VerdictDegraded,
		"58224/24940/vless": VerdictDegraded, "58224/24940/trojan": VerdictDegraded,
		"197207/16276/vless": VerdictOK, "44244/16276/vless": VerdictOK, "197207/12880/vless": VerdictOK,
	}
	checkVerdicts(t, src, "two halves", degraded)

	record(t, gdb, readAt(hour+50*60, p...), nil)
	checkVerdicts(t, src, "all at once", with(degraded,
		"197207/24940/vless", VerdictNodeDown, "197207/24940/trojan", VerdictNodeDown,
		"58224/24940/vless", VerdictNodeDown, "58224/24940/trojan", VerdictNodeDown))
}

// TestATunnelCountsOnceThisRunJudgedIt: a tunnel down only as the last run
// stored it, no status of this run having judged it, is no cut.
func TestATunnelCountsOnceThisRunJudgedIt(t *testing.T) {
	r := readAt(hour + 60)
	if rows := marksAt(r, []tunnels.View{{RelayID: 3, State: tunnels.Down, CheckedAt: hour}}, hour); len(rows) != 0 {
		t.Errorf("a stored state marked %+v", rows)
	}
	if rows := marksAt(r, []tunnels.View{{RelayID: 3, State: tunnels.Down, Judged: true}}, hour); len(rows) != 1 || rows[0].Kind != markCut || rows[0].NodeID != 3 {
		t.Errorf("a judged one marked %+v", rows)
	}
}

// TestALateBuildReadsWhatAnEarlyOneWould: an hour waiting for the shapes
// is built later with the marks of its own hour, whatever was read since;
// once built, nothing more is recorded for it and its marks go.
func TestALateBuildReadsWhatAnEarlyOneWould(t *testing.T) {
	c, _, _, now := setup(t)
	ctx := t.Context()
	early, _, err := build(ctx, c.Sources, hour)
	if err != nil {
		t.Fatal(err)
	}
	*now = time.Unix(hour-60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	shapes := c.Sources.Shapes
	c.Sources.Shapes = func() map[uint]map[string]ingest.Shape { return nil }
	*now = time.Unix(hour+3600+7*60, 0)
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.state(ctx, stateBuilt); got != strconv.FormatInt(hour-3600, 10) {
		t.Fatalf("built through %q with no shapes", got)
	}
	// Read ten hours on: nothing of it is the hour's, and the hour's marks
	// stay while it can still be built.
	*now = time.Unix(hour+10*3600, 0)
	record(t, c.DB, readAt(now.Unix(), fleetPaths()[4]), nil)
	c.Sources.Shapes = shapes
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var row Outbox
	if err := c.DB.Where("hour = ?", hour).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	late, err := decode(row.Body)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := cellVerdicts(early), cellVerdicts(*late); !maps.Equal(a, b) {
		t.Errorf("built late %v, on time %v", b, a)
	}
	// Built: a read stamped inside it (a slow flush) adds nothing, and the
	// next mark drops what it had.
	record(t, c.DB, readAt(hour+3599, fleetPaths()[4]), nil)
	if n := marksIn(t, c.DB, hour); n != 0 {
		t.Errorf("%d marks left of a built hour", n)
	}
}

// TestAMarkAfterTheBuildsReadIsCaught: a mark that lands between the
// build's read of an hour and its advance makes the hour be built again.
func TestAMarkAfterTheBuildsReadIsCaught(t *testing.T) {
	c, _, _, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour-60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	consent, from := c.state(ctx, stateOn), c.state(ctx, stateBuilt)
	n := marksIn(t, c.DB, hour)
	record(t, c.DB, readAt(hour+50*60, fleetPaths()[4]), nil)
	if moved, err := c.advance(ctx, consent, from, hour, nil, n); err != nil || moved {
		t.Fatalf("advanced past a mark it did not read: %v, %v", moved, err)
	}
	if moved, err := c.advance(ctx, consent, from, hour, nil, marksIn(t, c.DB, hour)); err != nil || !moved {
		t.Fatalf("did not advance with every mark read: %v, %v", moved, err)
	}
}

// TestAMarkDuringABuildRebuildsTheHour: a mark that lands while the hour
// is being built (here: when the build reads the shapes) holds the hour
// back, and the next build carries it.
func TestAMarkDuringABuildRebuildsTheHour(t *testing.T) {
	c, _, _, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour-60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	shapes, once := c.Sources.Shapes, false
	c.Sources.Shapes = func() map[uint]map[string]ingest.Shape {
		if !once {
			once = true
			record(t, c.DB, readAt(hour+59*60, fleetPaths()[4]), nil)
		}
		return shapes()
	}
	*now = time.Unix(hour+3600+7*60, 0)
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.state(ctx, stateBuilt); got != strconv.FormatInt(hour-3600, 10) {
		t.Fatalf("built through %q past a mark it did not read", got)
	}
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var row Outbox
	if err := c.DB.Where("hour = ?", hour).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	b, err := decode(row.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cellVerdicts(*b), with(fleetVerdicts(), "197207/16276/vless", VerdictDegraded); !maps.Equal(got, want) {
		t.Errorf("rebuilt %v, want %v", got, want)
	}
}

// TestAnHourPastKeepIsNotAdvanced: an hour that turned older than Keep
// while it was being built (a Mark may have dropped its records) is not
// queued.
func TestAnHourPastKeepIsNotAdvanced(t *testing.T) {
	c, _, _, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour-60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	consent, from := c.state(ctx, stateOn), c.state(ctx, stateBuilt)
	*now = time.Unix(hour, 0).Add(Keep + time.Hour)
	if moved, err := c.advance(ctx, consent, from, hour, nil, marksIn(t, c.DB, hour)); err != nil || moved {
		t.Fatalf("advanced an hour past Keep: %v, %v", moved, err)
	}
}

// TestMarksAreKeptWhileAnHourCanBeBuilt: on, an unbuilt hour's marks stay
// up to Keep and go after; a mark whose write fails takes its prune back
// with it; off, nothing is recorded or kept.
func TestMarksAreKeptWhileAnHourCanBeBuilt(t *testing.T) {
	c, _, _, now := setup(t)
	ctx := t.Context()
	fleetMarks := marksIn(t, c.DB, hour)
	if fleetMarks == 0 {
		t.Fatal("fleet recorded nothing")
	}
	*now = time.Unix(hour-60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	keep := 3600 * int64(Keep/time.Hour)
	record(t, c.DB, readAt(hour+keep), nil)
	if n := marksIn(t, c.DB, hour); n != fleetMarks {
		t.Errorf("%d marks left at Keep, want %d", n, fleetMarks)
	}
	// Past Keep, with the insert refused: the prune is undone.
	refuse := errors.New("refused")
	cb := c.DB.Callback().Create().Before("gorm:create")
	if err := cb.Register("refuse_marks", func(tx *gorm.DB) {
		if tx.Statement.Table == "hour_marks" {
			_ = tx.AddError(refuse)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := mark(ctx, c.DB, readAt(hour+keep+3600, fleetPaths()[4]), nil); !errors.Is(err, refuse) {
		t.Errorf("a refused write answered %v", err)
	}
	if n := marksIn(t, c.DB, hour); n != fleetMarks {
		t.Errorf("%d marks left after a failed write, want %d", n, fleetMarks)
	}
	if err := c.DB.Callback().Create().Remove("refuse_marks"); err != nil {
		t.Fatal(err)
	}
	record(t, c.DB, readAt(hour+keep+3600), nil)
	if n := marksIn(t, c.DB, hour); n != 0 {
		t.Errorf("%d marks left past Keep", n)
	}

	if err := c.SetOn(ctx, false); err != nil {
		t.Fatal(err)
	}
	in := hour + 5*3600
	record(t, c.DB, readAt(in+10*60, fleetPaths()[4]), nil)
	var all int64
	if err := c.DB.Model(&model.HourMark{}).Count(&all).Error; err != nil {
		t.Fatal(err)
	}
	if all != 0 {
		t.Errorf("off: %d marks kept", all)
	}
}

// fakePanel holds the key the Put gave it. failPut and failDelete refuse
// every call while set (sticky); lostPut and lostDelete carry the next call
// out but answer 504, once (one-shot: the call clears them).
type fakePanel struct {
	mu         sync.Mutex
	key        map[string]string
	deletes    int // Deletes carried out
	failPut    bool
	failDelete bool
	lostPut    bool
	lostDelete bool
}

func (p *fakePanel) Put(_ context.Context, path string, body any, _ any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failPut {
		return &panel.Error{Status: 502, Message: "down"}
	}
	if path != "/telemetry/contributor-key" {
		return &panel.Error{Status: 404}
	}
	p.key = body.(map[string]string)
	if p.lostPut {
		p.lostPut = false
		return &panel.Error{Status: http.StatusGatewayTimeout, Message: "timeout"}
	}
	return nil
}

func (p *fakePanel) Delete(_ context.Context, path string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failDelete {
		return &panel.Error{Status: 502, Message: "down"}
	}
	p.key = nil
	p.deletes++
	if p.lostDelete {
		p.lostDelete = false
		return &panel.Error{Status: http.StatusGatewayTimeout, Message: "timeout"}
	}
	return nil
}

// fakeCloud checks each request's signature as NX's cloud does and
// answers as told.
type fakeCloud struct {
	mu       sync.Mutex
	status   int
	onBatch  func() // after a batch is taken, outside the lock
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
			if hook := f.onBatch; hook != nil {
				f.mu.Unlock()
				hook()
				f.mu.Lock()
			}
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
	if fp.deletes == 0 {
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
	fc.report = `{"v":1,"extracted_at":` + strconv.FormatInt(hour+7200, 10) + `,"tier":"full","countries":[{"cc":"IR","from":1,"to":2,"contributors":"5-9","findings":[{"code":"strategy_works","severity":"info","asn":197207,"org":"MCCI","strategy":"vless/none/reality/direct","node_asn":0,"confidence":0.9}]}]}`
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

// TestAnHourWaitsForTheShapes: at a start the loop's first tick comes
// before the ingest has polled, so no shape is known; the closed hour with
// rows is not passed over, and the next tick, with the shapes in, builds and
// queues it.
func TestAnHourWaitsForTheShapes(t *testing.T) {
	c, _, fc, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour+60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	built := c.state(ctx, stateBuilt)
	*now = time.Unix(hour+3600+7*60, 0)
	shapes := c.Sources.Shapes
	none := func() map[uint]map[string]ingest.Shape { return nil }
	ready := false
	c.Sources.Ready = func() bool { return ready }
	for _, step := range []struct {
		name   string
		ready  bool
		shapes func() map[uint]map[string]ingest.Shape
	}{
		// Shapes held from before the first poll's flush are not trusted.
		{"not ready, shapes in", false, shapes},
		{"ready, no shapes", true, none},
	} {
		ready, c.Sources.Shapes = step.ready, step.shapes
		if err := c.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		if len(fc.batches) != 0 || c.state(ctx, stateBuilt) != built {
			t.Fatalf("%s: %d batches sent, built through %s (was %s)", step.name, len(fc.batches), c.state(ctx, stateBuilt), built)
		}
	}
	c.Sources.Shapes = shapes
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fc.batches) != 1 || fc.batches[0].Hour != hour || len(fc.batches[0].Cells) != 7 {
		t.Fatalf("with the shapes in, the cloud got %+v", fc.batches)
	}
	if c.state(ctx, stateBuilt) != strconv.FormatInt(hour, 10) {
		t.Fatalf("built through %s, want %d", c.state(ctx, stateBuilt), hour)
	}
}

// moreHours adds a row to each of n hours after hour.
func moreHours(t *testing.T, gdb *gorm.DB, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if err := gdb.Create(&model.PathHour{Hour: hour + int64(i)*3600, PathCell: model.PathCell{NodeID: 2, Inbound: "vless-reality-sni-www.example.com", ClientASN: 197207, Country: "IR", Network: "tcp"}, PathCounters: model.PathCounters{Accepted: 5, Authed: 5}}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

// TestOffDuringASendSendsNoMore: three batches are due; Mode B is turned
// off while the first is on its way. Nothing more goes out and nothing
// waits.
func TestOffDuringASendSendsNoMore(t *testing.T) {
	c, fp, fc, now := setup(t)
	ctx := t.Context()
	moreHours(t, c.DB, 2)
	*now = time.Unix(hour+60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	fc.onBatch = func() {
		fc.onBatch = nil
		if err := c.SetOn(ctx, false); err != nil {
			t.Error(err)
		}
	}
	*now = time.Unix(hour+3*3600+7*60, 0)
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fc.batches) != 1 {
		t.Fatalf("%d batches went out, want the one on its way when off was pressed", len(fc.batches))
	}
	var waiting int64
	c.DB.Model(&Outbox{}).Where("sent_at = 0").Count(&waiting)
	if waiting != 0 || c.state(ctx, stateBuilt) != "" || fp.deletes == 0 {
		t.Fatalf("after off: %d waiting, built through %q, %d Deletes", waiting, c.state(ctx, stateBuilt), fp.deletes)
	}
	_ = c.Tick(ctx)
	if len(fc.batches) != 1 {
		t.Fatal("a tick with Mode B off sent a batch")
	}
}

// TestAPostAfterAnOffKeepsTheOffsError: Mode B is turned off while a batch
// is on its way and the panel refuses the Delete; the post that lands after
// it does not wipe the reason the off wrote.
func TestAPostAfterAnOffKeepsTheOffsError(t *testing.T) {
	c, fp, fc, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour+60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	fp.failDelete = true
	fc.onBatch = func() {
		fc.onBatch = nil
		if err := c.SetOn(ctx, false); err == nil {
			t.Error("a refused Delete was not reported")
		}
	}
	*now = time.Unix(hour+3600+7*60, 0)
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fc.batches) != 1 {
		t.Fatalf("%d batches went out, want the one on its way", len(fc.batches))
	}
	if st, _ := c.Status(ctx); !st.Removing || !strings.Contains(st.Error, "did not remove") {
		t.Fatalf("the off's error after the post landed: %+v", st)
	}
}

// TestAConsentEndsTheSendBegunUnderIt: three batches are due; while the
// first is on its way Mode B is turned off and on again. The first lands,
// nothing of before the new on follows. Each half of the check pinned on its
// own: a batch dropped while the send runs is not posted, and a consent
// that changed stops the send.
func TestAConsentEndsTheSendBegunUnderIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		mid  func(t *testing.T, c *Cloud)
		want int
	}{
		{"off and on", func(t *testing.T, c *Cloud) {
			if err := c.SetOn(t.Context(), false); err != nil {
				t.Error(err)
			}
			if err := c.SetOn(t.Context(), true); err != nil {
				t.Error(err)
			}
		}, 1},
		{"the second batch dropped", func(t *testing.T, c *Cloud) {
			if err := c.DB.Where("hour = ?", hour+3600).Delete(&Outbox{}).Error; err != nil {
				t.Error(err)
			}
		}, 2},
		{"another consent", func(t *testing.T, c *Cloud) {
			if err := c.put(t.Context(), stateOn, "another"); err != nil {
				t.Error(err)
			}
		}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, fc, now := setup(t)
			ctx := t.Context()
			moreHours(t, c.DB, 2)
			*now = time.Unix(hour+60, 0)
			if err := c.SetOn(ctx, true); err != nil {
				t.Fatal(err)
			}
			fc.onBatch = func() {
				fc.onBatch = nil
				tc.mid(t, c)
			}
			*now = time.Unix(hour+3*3600+7*60, 0)
			if err := c.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			if len(fc.batches) != tc.want {
				t.Fatalf("%d batches went out, want %d", len(fc.batches), tc.want)
			}
		})
	}
}

// TestAConsentEndsTheBuildBegunUnderIt: three closed hours wait to be
// built; while the first is read, Mode B is turned off and on again.
// Nothing older than the new on's mark is queued and the mark does not move
// back. Each half of the check pinned on its own: a mark that moved, and a
// consent that changed under the same mark.
func TestAConsentEndsTheBuildBegunUnderIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		mid  func(t *testing.T, c *Cloud)
		mark int64
	}{
		{"off and on", func(t *testing.T, c *Cloud) {
			if err := c.SetOn(t.Context(), false); err != nil {
				t.Error(err)
			}
			if err := c.SetOn(t.Context(), true); err != nil {
				t.Error(err)
			}
		}, hour + 2*3600},
		// Within the hour of the first on, the new on writes the same mark:
		// only the consent tells them apart.
		{"off and on in the same hour", func(t *testing.T, c *Cloud) {
			clock := c.Now
			c.Now = func() time.Time { return time.Unix(hour+60, 0) }
			defer func() { c.Now = clock }()
			if err := c.SetOn(t.Context(), false); err != nil {
				t.Error(err)
			}
			if err := c.SetOn(t.Context(), true); err != nil {
				t.Error(err)
			}
		}, hour - 3600},
		{"the mark moved", func(t *testing.T, c *Cloud) {
			if err := c.put(t.Context(), stateBuilt, strconv.FormatInt(hour+2*3600, 10)); err != nil {
				t.Error(err)
			}
		}, hour + 2*3600},
		{"another consent", func(t *testing.T, c *Cloud) {
			if err := c.put(t.Context(), stateOn, "another"); err != nil {
				t.Error(err)
			}
		}, hour - 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, fc, now := setup(t)
			ctx := t.Context()
			moreHours(t, c.DB, 2)
			*now = time.Unix(hour+60, 0)
			if err := c.SetOn(ctx, true); err != nil {
				t.Fatal(err)
			}
			if c.state(ctx, stateBuilt) != strconv.FormatInt(hour-3600, 10) {
				t.Fatalf("built through %s after on", c.state(ctx, stateBuilt))
			}
			shapes, once := c.Sources.Shapes, false
			c.Sources.Shapes = func() map[uint]map[string]ingest.Shape {
				if !once {
					once = true
					tc.mid(t, c)
				}
				return shapes()
			}
			*now = time.Unix(hour+3*3600+7*60, 0)
			if err := c.Tick(ctx); err != nil {
				t.Fatal(err)
			}
			var queued []int64
			c.DB.Model(&Outbox{}).Order("hour").Pluck("hour", &queued)
			if len(queued) != 0 || len(fc.batches) != 0 || c.state(ctx, stateBuilt) != strconv.FormatInt(tc.mark, 10) {
				t.Fatalf("queued %v, sent %d, built through %s, want nothing and %d", queued, len(fc.batches), c.state(ctx, stateBuilt), tc.mark)
			}
		})
	}
}

// TestASecondOnKeepsTheWaitingHour: on while on is no new consent; the
// mark stays and the hour waiting for its build is still built.
func TestASecondOnKeepsTheWaitingHour(t *testing.T) {
	c, _, fc, now := setup(t)
	ctx := t.Context()
	*now = time.Unix(hour+60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	built := c.state(ctx, stateBuilt)
	*now = time.Unix(hour+3600+7*60, 0)
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c.state(ctx, stateBuilt) != built {
		t.Fatalf("a second on moved the mark from %s to %s", built, c.state(ctx, stateBuilt))
	}
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fc.batches) != 1 || fc.batches[0].Hour != hour {
		t.Fatalf("the waiting hour was not built: %+v", fc.batches)
	}
}

// TestOnAfterALostDeleteAnswerPutsTheKey: the panel carries out the Delete
// of an off but its answer is lost; the on after it puts the key again. And
// after an off whose Delete the panel refused, an on whose Put the panel
// refuses leaves the key counted for the next off, which removes it.
func TestOnAfterALostDeleteAnswerPutsTheKey(t *testing.T) {
	c, fp, _, _ := setup(t)
	ctx := t.Context()
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	fp.lostDelete = true
	if err := c.SetOn(ctx, false); err == nil || fp.key != nil {
		t.Fatalf("the Delete answered 504: err %v, key %v", err, fp.key)
	}
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(ctx); fp.key == nil || !st.Registered {
		t.Fatalf("on after the lost answer: key %v, %+v", fp.key, st)
	}

	fp.failDelete = true
	_ = c.SetOn(ctx, false) // the panel keeps the key
	fp.failDelete, fp.failPut = false, true
	if err := c.SetOn(ctx, true); err == nil {
		t.Fatal("a refused Put was not reported")
	}
	if st, _ := c.Status(ctx); st.Registered {
		t.Fatalf("registered while the panel took no Put: %+v", st)
	}
	deletes := fp.deletes
	if err := c.SetOn(ctx, false); err != nil || fp.deletes != deletes+1 {
		t.Fatalf("the off after a refused Put: err %v, %d Deletes, want one", err, fp.deletes-deletes)
	}
}

// TestOffAfterALostPutAnswerDeletesTheKey: the panel carries out the Put
// of an on but its answer is lost; the off after it still removes the key.
func TestOffAfterALostPutAnswerDeletesTheKey(t *testing.T) {
	c, fp, _, _ := setup(t)
	ctx := t.Context()
	fp.lostPut = true
	if err := c.SetOn(ctx, true); err == nil || fp.key == nil {
		t.Fatalf("the Put answered 504: err %v, key %v", err, fp.key)
	}
	if st, _ := c.Status(ctx); st.Registered {
		t.Fatalf("registered on a lost answer: %+v", st)
	}
	if err := c.SetOn(ctx, false); err != nil || fp.deletes != 1 || fp.key != nil {
		t.Fatalf("the off after a lost Put answer: err %v, %d Deletes, key %v", err, fp.deletes, fp.key)
	}
}

// TestOffWithoutPanelCredentialsClearsTheirError: on with no panel
// credentials leaves "no credentials" in Status; with no key registered
// there is nothing to remove, so off clears that error instead of showing
// it on the off page.
func TestOffWithoutPanelCredentialsClearsTheirError(t *testing.T) {
	c, _, _, _ := setup(t)
	ctx := t.Context()
	c.Panel = func() Panel { return nil }
	_ = c.SetOn(ctx, true)
	_ = c.Tick(ctx)
	if st, _ := c.Status(ctx); st.Error == "" {
		t.Fatalf("on without panel credentials shows no error: %+v", st)
	}
	if err := c.SetOn(ctx, false); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Status(ctx); st.Error != "" || st.Removing {
		t.Fatalf("off kept an error that no longer applies: %+v", st)
	}
}

// TestOnClearsTheErrorOfAFailedDelete: the panel refuses the Delete; the
// on after it does not show that error, and a Put that went through clears
// the error of one that did not.
func TestOnClearsTheErrorOfAFailedDelete(t *testing.T) {
	c, fp, _, _ := setup(t)
	ctx := t.Context()
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	fp.failDelete = true
	_ = c.SetOn(ctx, false)
	fp.failDelete, fp.failPut = false, true
	_ = c.SetOn(ctx, true)
	if st, _ := c.Status(ctx); st.Error != "" {
		t.Fatalf("an error still shows after on: %+v", st)
	}
	_ = c.Tick(ctx)
	if st, _ := c.Status(ctx); !strings.Contains(st.Error, "did not take") {
		t.Fatalf("a refused Put in a tick: %+v", st)
	}
	fp.failPut = false
	_ = c.Tick(ctx) // nothing to send: only the Put clears it
	if st, _ := c.Status(ctx); st.Error != "" || !st.Registered {
		t.Fatalf("after the Put went through: %+v", st)
	}
}

// TestOnWithoutAMarkBuildsNothingOlder: on stands but the hour it was given
// at is missing; the first tick starts from the hour in progress and never
// sends an hour from before.
func TestOnWithoutAMarkBuildsNothingOlder(t *testing.T) {
	c, _, fc, _ := setup(t)
	ctx := t.Context()
	if err := c.put(ctx, stateOn, rand.Text()); err != nil {
		t.Fatal(err)
	}
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	_ = c.Tick(ctx)
	if len(fc.batches) != 0 || c.state(ctx, stateBuilt) != strconv.FormatInt(hour, 10) {
		t.Fatalf("sent %+v, built through %q, want nothing and %d", fc.batches, c.state(ctx, stateBuilt), hour)
	}
}

// TestAFailedDeleteIsRetried: the panel does not take the Delete when Mode
// B is turned off; the key stays registered, Status says why, and the next
// tick removes it.
func TestAFailedDeleteIsRetried(t *testing.T) {
	c, fp, _, _ := setup(t)
	ctx := t.Context()
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	fp.failDelete = true
	if err := c.SetOn(ctx, false); err == nil {
		t.Fatal("a failed Delete was not reported")
	}
	st, _ := c.Status(ctx)
	if st.On || !st.Registered || !st.Removing || !strings.Contains(st.Error, "did not remove") || fp.deletes > 0 {
		t.Fatalf("after a failed Delete: %+v", st)
	}
	fp.failDelete = false
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	st, _ = c.Status(ctx)
	if fp.deletes == 0 || st.Registered || st.Removing || st.Error != "" {
		t.Fatalf("the tick did not remove the key: %d Deletes, %+v", fp.deletes, st)
	}
}

// TestADamagedKeyIsShownAndOffDropsIt: a stored seed that does not decode
// is never replaced silently; Status says so, and off then on makes a new
// key.
func TestADamagedKeyIsShownAndOffDropsIt(t *testing.T) {
	c, _, _, _ := setup(t)
	ctx := t.Context()
	if err := c.put(ctx, stateKey, "not-a-seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.key(ctx); err == nil {
		t.Fatal("a damaged seed was read as a key")
	}
	if err := c.SetOn(ctx, true); err == nil {
		t.Fatal("on with a damaged key")
	}
	st, _ := c.Status(ctx)
	if !strings.Contains(st.Error, "damaged") || st.Fingerprint != "" {
		t.Fatalf("status = %+v", st)
	}
	if c.state(ctx, stateKey) != "not-a-seed" {
		t.Fatal("the damaged seed was replaced without the admin")
	}
	if err := c.SetOn(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	if st, _ = c.Status(ctx); st.Fingerprint == "" || st.Error != "" || !st.Registered {
		t.Fatalf("after off and on: %+v", st)
	}
}

// TestTheSwitchHonoursTheRequest: a toggle waiting behind a panel call
// gives up when its request ends.
func TestTheSwitchHonoursTheRequest(t *testing.T) {
	c, _, _, _ := setup(t)
	if err := c.lock(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer c.unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := c.SetOn(ctx, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the request's deadline", err)
	}
}

// TestRefusalsArePermanentOrRetried: what the cloud answers decides
// whether a batch is tried again.
func TestRefusalsArePermanentOrRetried(t *testing.T) {
	c, _, fc, _ := setup(t)
	ctx := t.Context()
	k, err := c.key(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for status, perm := range map[int]bool{400: true, 401: true, 410: true, 413: true, 415: true, 403: false, 425: false, 429: false, 500: false, 503: false} {
		fc.status = status
		err := c.post(ctx, k, "/v1/batch", []byte("{}"), BatchContext, nil, nil)
		var se *sendError
		if !errors.As(err, &se) || se.status != status || se.permanent != perm {
			t.Errorf("%d: err = %v, want permanent %v", status, err, perm)
		}
	}
	// A 410 batch is kept unsent, never retried, and Status calls it refused.
	fc.status = 410
	c.Now = func() time.Time { return time.Unix(hour+60, 0) }
	if err := c.SetOn(ctx, true); err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return time.Unix(hour+3600+7*60, 0) }
	_ = c.Tick(ctx)
	st, _ := c.Status(ctx)
	if st.Failed != 1 || st.Pending != 0 || len(st.Recent) != 1 || !st.Recent[0].Refused {
		t.Fatalf("after a 410: %+v", st)
	}
	// A 429 waits and is tried again.
	moreHours(t, c.DB, 1)
	fc.status = 429
	c.Now = func() time.Time { return time.Unix(hour+2*3600+7*60, 0) }
	_ = c.Tick(ctx)
	if st, _ = c.Status(ctx); st.Pending != 1 || st.Failed != 1 {
		t.Fatalf("after a 429: %+v", st)
	}
}

// TestClipCountsUTF16: clip cuts to n UTF-16 code units, as the cloud
// counts them, never inside a character, and leaves an invalid byte as it
// was.
func TestClipCountsUTF16(t *testing.T) {
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{
		{"", 3, ""},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"ab\U0001F600", 3, "ab"}, // an astral character counts two: never split
		{"ab\U0001F600", 4, "ab\U0001F600"},
		{"a\xffbc", 2, "a\xff"}, // an invalid byte stays as it was
		{"a\xff", 5, "a\xff"},
	} {
		if got := clip(tc.in, tc.n); got != tc.want {
			t.Errorf("clip(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// TestLessOrdersByTheKeyInTurn: cells are ordered by the AS number first
// and by each later field of the key only when the earlier ones are equal,
// down to the network.
func TestLessOrdersByTheKeyInTurn(t *testing.T) {
	a := Cell{ASN: 1, CC: "IR", Verdict: "z"}
	b := Cell{ASN: 2, CC: "AA", Verdict: "a"}
	if !less(a, b) || less(b, a) || less(a, a) {
		t.Error("the AS number does not come first")
	}
	c := a
	c.Network = "udp"
	a.Network = "tcp"
	if !less(a, c) || less(c, a) {
		t.Error("cells equal up to the network are not ordered by it")
	}
}

// TestRegionsAlikeUpToTheClipAreOneCell: two regions that differ only past
// what is sent are one cell, summed: the cloud refuses a batch that lists a
// cell twice.
func TestRegionsAlikeUpToTheClipAreOneCell(t *testing.T) {
	gdb := openDB(t)
	src := fleet(t, gdb)
	// Outside the basic plane a character is two UTF-16 units: sixty of
	// them fit the column's 96 characters and pass the cloud's 96 units.
	long := strings.Repeat("\U000103A0", 60)
	for _, tail := range []string{"one", "two"} {
		row := model.PathHour{Hour: hour, PathCell: model.PathCell{
			NodeID: 2, Inbound: "vless-reality-sni-www.example.com", ClientASN: 197207, Country: "IR", Region: long + tail, Network: "tcp", SourceKind: "peer",
		}, PathCounters: model.PathCounters{Accepted: 10, Authed: 9}}
		if err := gdb.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	b, _, err := build(t.Context(), src, hour)
	if err != nil {
		t.Fatal(err)
	}
	clipped := strings.Repeat("\U000103A0", 48)
	n := 0
	for _, c := range b.Cells {
		if c.Region == clipped {
			n++
			if c.Accepted != 20 {
				t.Errorf("the clipped cell holds %d accepted, want 20", c.Accepted)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d cells for the clipped region, want 1", n)
	}
}
