package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
)

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	dir := t.TempDir()
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(dir, "insight.db")})
	if err != nil {
		t.Fatal(err)
	}
	return gdb
}

func netDB(t *testing.T) *netinfo.DB {
	t.Helper()
	var asn strings.Builder
	asn.WriteString("5.160.0.0\t5.160.255.255\t44244\tIR\tIRANCELL-AS\n")
	asn.WriteString("2.176.0.0\t2.191.255.255\t58224\tIR\tTCI\n")
	asn.WriteString("88.198.0.0\t88.198.255.255\t24940\tDE\tHETZNER-AS\n")
	// 40 more one-/24 ASNs, for the top-K folding.
	for i := range 40 {
		fmt.Fprintf(&asn, "100.%d.0.0\t100.%d.0.255\t%d\tRU\tAS-%d\n", i, i, 64600+i, i)
	}
	a, err := netinfo.ReadASN(strings.NewReader(asn.String()))
	if err != nil {
		t.Fatal(err)
	}
	c, err := netinfo.ReadCity(strings.NewReader("5.160.0.0,5.160.255.255,AS,IR,Isfahan,Isfahan,0,0\n"), []string{"IR"})
	if err != nil {
		t.Fatal(err)
	}
	d := &netinfo.DB{}
	d.SetASN(a)
	d.SetCity(c)
	return d
}

// fakePanel answers the two calls Insight makes, and records the cursors
// it was asked from.
type fakePanel struct {
	mu      sync.Mutex
	samples []Sample
	nodes   []panelNode
	asked   []string
	status  int
}

func (f *fakePanel) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, path)
	if f.status != 0 {
		return &panel.Error{Status: f.status, Message: "no"}
	}
	var body any
	switch {
	case strings.HasPrefix(path, "/telemetry/paths"):
		var since uint64
		fmt.Sscanf(path[strings.Index(path, "since=")+6:], "%d", &since)
		p := page{Active: true, Samples: []Sample{}, Cursor: since}
		for _, s := range f.samples {
			if s.Cursor > since {
				p.Samples = append(p.Samples, s)
				p.Cursor = s.Cursor
			}
		}
		body = p
	case strings.HasPrefix(path, "/nodes"):
		body = map[string]any{"items": f.nodes}
	default:
		return &panel.Error{Status: http.StatusNotFound}
	}
	raw, _ := json.Marshal(body)
	return json.Unmarshal(raw, out)
}

func (f *fakePanel) add(s Sample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.Cursor = uint64(len(f.samples) + 1)
	f.samples = append(f.samples, s)
}

var hour = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC).Unix()

// atHour is the ingest's clock in these tests: within the hour the samples
// are stamped in, so none reads as a node with a wrong clock.
func atHour() time.Time { return time.Unix(hour+3500, 0) }

// TestASampleBecomesAnHourlyRowWithoutItsPrefix is PT4's done_when: a
// polled sample is an hourly row with the client's ASN and region, the
// prefix nowhere in the database, and the cursor kept with it so the next
// poll asks only for what is new.
func TestASampleBecomesAnHourlyRowWithoutItsPrefix(t *testing.T) {
	gdb := openDB(t)
	fp := &fakePanel{}
	in := &Ingest{Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return fp }}
	fp.add(Sample{
		NodeID: 3, DateTime: hour + 125, Inbound: "vless-reality", Network: "tcp", Prefix: "5.160.7.0/24",
		SourceKind: "peer", Accepted: 10, Authed: 7, Failed: map[string]uint32{"auth": 2, "timeout": 1}, EarlyClose: 1,
		DurP50: 60, RTTP50: 150, RetransPPM: 20000, Up: 1000, Down: 9000,
	})
	fp.add(Sample{
		NodeID: 3, DateTime: hour + 1800, Inbound: "vless-reality", Network: "tcp", Prefix: "5.160.9.0/24",
		SourceKind: "peer", Accepted: 5, Authed: 3, RTTP50: 250,
		Replayed: 2, FollowUpFail: 1, Failed: map[string]uint32{"quic_initial_bad": 4},
	})
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := in.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var rows []model.PathHour
	if err := gdb.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want the two /24s of one ASN in one hour folded into one cell", rows)
	}
	r := rows[0]
	if r.Hour != hour || r.NodeID != 3 || r.ClientASN != 44244 || r.Country != "IR" || r.Region != "Isfahan" ||
		r.Accepted != 15 || r.Authed != 10 || r.FailedAuth != 2 || r.FailedTimeout != 1 || r.EarlyClose != 1 ||
		r.RTTSum != 150*7+250*3 || r.RTTN != 10 || r.Up != 1000 || r.Down != 9000 ||
		r.Replayed != 2 || r.FollowUpFail != 1 || r.FailedQUIC != 4 || r.FailedOther != 0 {
		t.Fatalf("row = %+v", r)
	}
	assertNoPrefix(t, gdb)

	fp.add(Sample{NodeID: 3, DateTime: hour + 3000, Inbound: "vless-reality", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 1})
	fresh := &Ingest{Now: atHour, DB: gdb, Net: in.Net, Panel: in.Panel} // a restart
	if err := fresh.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if last := fp.asked[len(fp.asked)-1]; !strings.Contains(last, "since=2&") {
		t.Fatalf("after a restart the poll asked %q, want since=2", last)
	}
	if err := fresh.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var again model.PathHour
	gdb.First(&again, r.ID)
	if again.Accepted != 16 || again.Replayed != 2 {
		t.Fatalf("the next flush did not add into the cell: %d", again.Accepted)
	}
}

// assertNoPrefix: no column of any table is a prefix or an address of a
// client, and no stored value looks like the prefixes polled.
func assertNoPrefix(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	for _, m := range model.All() {
		cols, err := gdb.Migrator().ColumnTypes(m)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cols {
			if n := c.Name(); strings.Contains(n, "prefix") || n == "client_ip" || n == "source" {
				t.Errorf("table %T has a column %q", m, n)
			}
		}
	}
	var dump []map[string]any
	gdb.Raw("SELECT * FROM path_hours").Scan(&dump)
	for _, row := range dump {
		for k, v := range row {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "5.160.") {
				t.Errorf("path_hours.%s holds %q", k, s)
			}
		}
	}
}

// TestTopKFoldsTheRest: past TopK client ASNs on one node and inbound in an
// hour, the rest share the OtherASN cell, with no country or region; the
// busiest are the ones kept, also across flushes.
func TestTopKFoldsTheRest(t *testing.T) {
	gdb := openDB(t)
	fp := &fakePanel{}
	in := &Ingest{Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return fp }}
	for i := range 35 {
		fp.add(Sample{NodeID: 1, DateTime: hour, Inbound: "in", Network: "tcp", Prefix: fmt.Sprintf("100.%d.0.0/24", i), SourceKind: "peer", Accepted: uint32(100 - i)})
	}
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := in.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	fp.add(Sample{NodeID: 1, DateTime: hour, Inbound: "in", Network: "tcp", Prefix: "100.39.0.0/24", SourceKind: "peer", Accepted: 1000})
	fresh := &Ingest{Now: atHour, DB: gdb, Net: in.Net, Panel: in.Panel}
	if err := fresh.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var cells int64
	gdb.Model(&model.PathHour{}).Where("client_asn <> ?", OtherASN).Count(&cells)
	var other model.PathHour
	if err := gdb.Where("client_asn = ?", OtherASN).First(&other).Error; err != nil {
		t.Fatal(err)
	}
	// 30 kept (the busiest: 100 … 71), 5 folded (70 … 66), then a 36th ASN
	// arriving later folds too, however busy, because the hour is full.
	if cells != TopK || other.Accepted != 70+69+68+67+66+1000 || other.Country != "" {
		t.Fatalf("own cells %d, other %+v", cells, other)
	}
	var kept model.PathHour
	if err := gdb.Where("client_asn = ?", 64600).First(&kept).Error; err != nil || kept.Accepted != 100 {
		t.Fatalf("the busiest ASN is not kept: %+v %v", kept, err)
	}
}

// TestPollStates: a panel without the route and a token without the scope
// say so, instead of failing silently.
func TestPollStates(t *testing.T) {
	gdb := openDB(t)
	fp := &fakePanel{status: http.StatusNotFound}
	in := &Ingest{Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return fp }}
	_ = in.Poll(t.Context())
	if s := in.Status(); s.State != StateUnsupported {
		t.Fatalf("404: %+v", s)
	}
	fp.status = http.StatusForbidden
	_ = in.Poll(t.Context())
	if s := in.Status(); s.State != StateNoScope {
		t.Fatalf("403: %+v", s)
	}
	fp.status = 0
	if err := in.Poll(t.Context()); err != nil || in.Status().State != StateOK {
		t.Fatalf("ok: %v %+v", err, in.Status())
	}
	unregistered := &Ingest{Now: atHour, DB: gdb, Panel: func() Getter { return nil }}
	if err := unregistered.Poll(t.Context()); err != nil || unregistered.Status().State != StateWaiting {
		t.Fatalf("unregistered: %v %+v", err, unregistered.Status())
	}
}

// TestNodeNetinfoAndOverrides is PT4's second done_when: a node's host
// ASN and city are filled from its address, and an override stays over a
// later refresh.
func TestNodeNetinfoAndOverrides(t *testing.T) {
	gdb := openDB(t)
	cityFile := filepath.Join(t.TempDir(), "city.csv.gz")
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte("88.198.0.0,88.198.255.255,EU,DE,Saxony,Falkenstein,0,0\n"))
	w.Close()
	if err := os.WriteFile(cityFile, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	fp := &fakePanel{nodes: []panelNode{
		{ID: 1, Name: "fsn", Address: "10.0.0.1", LinkAddress: "Main|88.198.10.20,backup.example.com"},
		{ID: 2, Name: "named", Address: "node.example.com"},
	}}
	n := &Nodes{
		DB: gdb, Net: netDB(t), Panel: func() Getter { return fp }, CityFile: func() string { return cityFile },
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "node.example.com" {
				return []netip.Addr{netip.MustParseAddr("5.160.1.1")}, nil
			}
			return nil, fmt.Errorf("no %s", host)
		},
	}
	if err := n.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	var fsn, named model.NodeNetinfo
	gdb.First(&fsn, 1)
	gdb.First(&named, 2)
	if fsn.Address != "88.198.10.20" || fsn.ASN != 24940 || fsn.Org != "HETZNER-AS" || fsn.Country != "DE" || fsn.City != "Falkenstein" {
		t.Fatalf("fsn = %+v", fsn)
	}
	if named.ASN != 44244 {
		t.Fatalf("a node by name was not resolved: %+v", named)
	}
	if err := Override(gdb, 1, 0, "", "", "Nuremberg"); err != nil {
		t.Fatal(err)
	}
	if err := n.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	gdb.First(&fsn, 1)
	if _, _, _, city := fsn.Effective(); city != "Nuremberg" || fsn.City != "Falkenstein" {
		t.Fatalf("the override did not hold over a refresh: %+v", fsn)
	}
	fp.nodes = fp.nodes[:1]
	if err := n.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	var count int64
	gdb.Model(&model.NodeNetinfo{}).Count(&count)
	if count != 1 {
		t.Fatalf("a node removed on the panel stayed: %d rows", count)
	}
	if err := Override(gdb, 9, 1, "", "", ""); err == nil {
		t.Fatal("an override of an unknown node was taken")
	}
}

// TestCompactFoldsHoursIntoDays: hours past PathHourDays become one row per
// day and cell; days past PathDayDays go.
func TestCompactFoldsHoursIntoDays(t *testing.T) {
	gdb := openDB(t)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	old := now.AddDate(0, 0, -10).Truncate(24 * time.Hour).Unix()
	cell := model.PathCell{NodeID: 1, Inbound: "in", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"}
	for i := range 3 {
		row := model.PathHour{Hour: old + int64(i)*3600, PathCell: cell, PathCounters: model.PathCounters{Accepted: 10, RTTSum: 100, RTTN: 1}}
		if err := gdb.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	recent := model.PathHour{Hour: now.Add(-time.Hour).Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 1}}
	ancient := model.PathDay{Day: now.AddDate(0, 0, -100).Truncate(24 * time.Hour).Unix(), PathCell: cell}
	gdb.Create(&recent)
	gdb.Create(&ancient)
	if err := Compact(t.Context(), gdb, now); err != nil {
		t.Fatal(err)
	}
	var hours []model.PathHour
	var days []model.PathDay
	gdb.Find(&hours)
	gdb.Find(&days)
	if len(hours) != 1 || hours[0].ID != recent.ID {
		t.Fatalf("hours = %+v", hours)
	}
	if len(days) != 1 || days[0].Day != old || days[0].Accepted != 30 || days[0].RTTN != 3 {
		t.Fatalf("days = %+v", days)
	}
}

// TestPostgres runs the flush, the top-K folding and the compaction on
// PostgreSQL when NX_INSIGHT_PG_DSN names one: the upsert's SQL is the one
// thing that differs between the two databases.
func TestPostgres(t *testing.T) {
	dsn := os.Getenv("NX_INSIGHT_PG_DSN")
	if dsn == "" {
		t.Skip("NX_INSIGHT_PG_DSN names no database")
	}
	gdb, err := db.Open(config.Config{Driver: config.DriverPostgres, DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range model.All() {
		gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m)
	}
	fp := &fakePanel{}
	in := &Ingest{Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return fp }}
	for i := range 2 {
		fp.add(Sample{NodeID: 1, DateTime: hour, Inbound: "in", Network: "tcp", Prefix: "5.160.1.0/24", SourceKind: "peer", Accepted: uint32(i + 1)})
		if err := in.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := in.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var r model.PathHour
	if err := gdb.First(&r).Error; err != nil || r.Accepted != 3 {
		t.Fatalf("row %+v, %v", r, err)
	}
	if err := Compact(t.Context(), gdb, time.Unix(hour, 0).AddDate(0, 0, 9)); err != nil {
		t.Fatal(err)
	}
	var d model.PathDay
	if err := gdb.First(&d).Error; err != nil || d.Accepted != 3 {
		t.Fatalf("day %+v, %v", d, err)
	}
}

// TestACursorThePanelNeverGaveIsLetGo: a panel that restarted (or another
// panel, or a restored database) answers our cursor with gap and everything
// it holds, numbered from somewhere below it. Its cursor is taken — kept,
// ours would ask for and add all of that again on every poll.
func TestACursorThePanelNeverGaveIsLetGo(t *testing.T) {
	gdb := openDB(t)
	fp := &gapPanel{}
	var fed []bool
	gaps := 0
	in := &Ingest{
		Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return fp },
		Fed: func(ok bool, _ []NodeState) { fed = append(fed, ok) }, Gapped: func() { gaps++ },
	}
	if err := gdb.Create(&model.State{Key: stateCursor, Value: "900000"}).Error; err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := in.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if err := in.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	var rows []model.PathHour
	gdb.Find(&rows)
	if len(rows) != 1 || rows[0].Accepted != 10 {
		t.Fatalf("rows = %+v, want the one sample counted once", rows)
	}
	if fmt.Sprint(fed) != "[true true true]" || gaps != 1 {
		t.Fatalf("fed = %v, gaps = %d, want three good polls and the gap reported once", fed, gaps)
	}
}

// gapPanel holds one sample at cursor 7 and answers any cursor above it the
// way the panel does: everything, with gap.
type gapPanel struct{}

func (gapPanel) Get(_ context.Context, path string, out any) error {
	var since uint64
	fmt.Sscanf(path[strings.Index(path, "since=")+6:], "%d", &since)
	p := page{Active: true, Samples: []Sample{}, Cursor: 7}
	if since > 7 {
		p.Gap, since = true, 0
	}
	if since < 7 {
		p.Samples = []Sample{{Cursor: 7, NodeID: 1, DateTime: hour + 10, Inbound: "in", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 10}}
	}
	raw, _ := json.Marshal(p)
	return json.Unmarshal(raw, out)
}

// TestNothingIsPolledBeforeTheNetworksAreKnown: a sample looked up against
// an empty table would be stored for good with no network and no country.
func TestNothingIsPolledBeforeTheNetworksAreKnown(t *testing.T) {
	gdb := openDB(t)
	fp := &fakePanel{}
	fp.add(Sample{NodeID: 1, DateTime: hour + 10, Inbound: "in", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 10})
	in := &Ingest{Now: atHour, DB: gdb, Net: &netinfo.DB{}, Panel: func() Getter { return fp }}
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fp.asked) != 0 || in.Status().Pending != 0 {
		t.Fatalf("polled with no network table: %v", fp.asked)
	}
	in.Net = netDB(t)
	if err := in.Poll(t.Context()); err != nil || in.Status().Pending != 1 {
		t.Fatalf("with the table: pending %d, %v", in.Status().Pending, err)
	}
}

// TestANodeWithAWrongClockIsNotCounting: its samples are dropped for their
// timestamp, and the feed says so of the node — its paths would otherwise
// read as silent, and silence as a block.
func TestANodeWithAWrongClockIsNotCounting(t *testing.T) {
	gdb := openDB(t)
	fp := &fakePanel{}
	fp.add(Sample{NodeID: 1, DateTime: hour + 10, Inbound: "in", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 10})
	fp.add(Sample{NodeID: 2, DateTime: hour - 30*3600, Inbound: "in", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 10})
	var got []NodeState
	in := &Ingest{Now: atHour, DB: gdb, Net: netDB(t), Panel: func() Getter { return skewPanel{fakePanel: fp} }, Fed: func(_ bool, nodes []NodeState) { got = nodes }}
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].State != "on" || got[1].State != StateSkewed || in.Status().Skewed != 1 || in.Status().Pending != 1 {
		t.Fatalf("nodes = %+v, status %+v", got, in.Status())
	}
}

// skewPanel is fakePanel listing two nodes as counting, or the nodes it
// names.
type skewPanel struct {
	*fakePanel
	nodes []NodeState
}

func (p skewPanel) Get(ctx context.Context, path string, out any) error {
	if err := p.fakePanel.Get(ctx, path, out); err != nil {
		return err
	}
	if pg, ok := out.(*page); ok {
		pg.Nodes = []NodeState{{ID: 1, State: "on"}, {ID: 2, State: "on"}}
		if p.nodes != nil {
			pg.Nodes = p.nodes
		}
	}
	return nil
}

// TestAnEmptyListStaysAList: a poll listing no node — the deleted one's
// skewed samples still in the panel's buffer — is "every node off", not "not
// known", which would keep the old list counting.
func TestAnEmptyListStaysAList(t *testing.T) {
	fp := &fakePanel{}
	fp.add(Sample{NodeID: 2, DateTime: hour - 30*3600, Inbound: "in", Network: "tcp", Prefix: "5.160.7.0/24", SourceKind: "peer", Accepted: 10})
	got := []NodeState{{ID: 9}}
	in := &Ingest{Now: atHour, DB: openDB(t), Net: netDB(t), Panel: func() Getter { return skewPanel{fp, []NodeState{}} }, Fed: func(_ bool, nodes []NodeState) { got = nodes }}
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got == nil || len(got) != 0 || in.Status().Skewed != 1 {
		t.Fatalf("nodes = %#v, status %+v", got, in.Status())
	}
}

// TestCountingIsTheNodesListedOn: a node listed off, skewed or not listed at
// all (deleted) is not counting; a poll with no list is not known.
func TestCountingIsTheNodesListedOn(t *testing.T) {
	if Counting(nil) != nil {
		t.Fatal("no list read as a list")
	}
	got := Counting([]NodeState{{ID: 1, State: StateNodeOn}, {ID: 2, State: "off"}, {ID: 3, State: StateSkewed}})
	if len(got) != 1 || !got[1] {
		t.Fatalf("counting = %v, want only node 1", got)
	}
	if got := Counting([]NodeState{}); got == nil || len(got) != 0 {
		t.Fatalf("an empty list = %v, want every node off", got)
	}
}
