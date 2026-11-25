package detect_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

// openDB is a fresh SQLite database, or the PostgreSQL one
// NX_INSIGHT_PG_DSN names, emptied, so the detector's SQL is run on both.
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
		for _, m := range append(model.All(), detect.Tables()...) {
			gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m)
		}
	}
	return gdb
}

// clock is a test clock the detector reads.
type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) step(d time.Duration) { c.t = c.t.Add(d) }
func normal(gdb *gorm.DB, t *testing.T, k detect.Key) {
	t.Helper()
	b := detect.Baseline{
		NodeID: k.Node, Inbound: k.Inbound, ASN: k.ASN, Network: k.Network, Slot: detect.RecentSlot,
		N: 24, MeanAuthed: 120, VarAuthed: 100, MeanFail: 0.03, VarFail: 0.0004, MeanEarly: 0.05, VarEarly: 0.001,
	}
	if err := gdb.Create(&b).Error; err != nil {
		t.Fatal(err)
	}
}

// traffic is one five-minute bucket of a path: a healthy one carries 10
// authenticated connections (120 an hour) with a few failures.
func traffic(d *detect.Detector, k detect.Key, accepted, authed, failed uint64) {
	d.Observe(k, model.PathCounters{Accepted: accepted, Authed: authed, FailedAuth: failed})
}

func kinds(t *testing.T, gdb *gorm.DB) []string {
	t.Helper()
	var alerts []detect.Alert
	gdb.Order("id").Find(&alerts)
	out := make([]string, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, a.Kind)
	}
	return out
}

// TestABlockedPathAlertsAndRecovers: a
// path whose handshakes start failing is degraded on the second bad
// evaluation (ten minutes), not the first, and recovered on the second good
// one after it clears; one bad window alone moves nothing.
func TestABlockedPathAlertsAndRecovers(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	var sent []detect.Alert
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	k := detect.Key{Node: 1, Inbound: "vless-reality", ASN: 44244, Network: "tcp"}
	other := detect.Key{Node: 2, Inbound: "vless-reality", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	normal(gdb, t, other)
	eval := func(acc, auth, fail uint64) {
		t.Helper()
		for range detect.Buckets {
			traffic(d, k, acc, auth, fail)
			traffic(d, other, 11, 10, 0)
			c.step(detect.BucketEvery)
		}
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	eval(11, 10, 0)
	eval(11, 10, 0)
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a healthy path raised %v", got)
	}
	eval(50, 2, 45) // blocked: one bad window
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("one bad window raised %v", got)
	}
	eval(50, 2, 45)
	if got := kinds(t, gdb); len(got) != 1 || got[0] != detect.KindDegraded {
		t.Fatalf("after two bad windows: %v", got)
	}
	if !d.Degraded()[k] || d.Degraded()[other] {
		t.Fatalf("degraded = %v", d.Degraded())
	}
	eval(11, 10, 0)
	eval(11, 10, 0)
	if got := kinds(t, gdb); len(got) != 2 || got[1] != detect.KindRecovered {
		t.Fatalf("after it cleared: %v", got)
	}
	_ = sent
}

// TestTrafficThatStopsIsADrop: a path whose connections stop arriving at all
// is degraded for the drop, not left silent for lack of samples.
func TestTrafficThatStopsIsADrop(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	k := detect.Key{Node: 1, Inbound: "trojan", ASN: 58224, Network: "tcp"}
	normal(gdb, t, k)
	for range 2 {
		c.step(detect.BucketEvery * detect.Buckets)
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var a detect.Alert
	if err := gdb.First(&a).Error; err != nil || a.Kind != detect.KindDegraded || a.Reason != "drop" {
		t.Fatalf("alert = %+v, %v", a, err)
	}
}

// TestAWholeASNDownIsOneOutage: every path of a client ASN down on
// two nodes is one asn.outage, with no per-path alert, and its end is one
// asn.recovered.
func TestAWholeASNDownIsOneOutage(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	keys := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 1, Inbound: "b", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"},
	}
	for _, k := range keys {
		normal(gdb, t, k)
	}
	eval := func(ok bool) {
		t.Helper()
		for range detect.Buckets {
			if ok {
				for _, k := range keys {
					traffic(d, k, 11, 10, 0)
				}
			}
			c.step(detect.BucketEvery)
		}
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	eval(false)
	eval(false)
	if got := kinds(t, gdb); len(got) != 1 || got[0] != detect.KindOutage {
		t.Fatalf("a whole ASN down: %v", got)
	}
	if !d.Outages()[44244] {
		t.Fatal("no outage recorded")
	}
	eval(true)
	eval(true)
	if got := kinds(t, gdb); len(got) != 2 || got[1] != detect.KindOutageEnd {
		t.Fatalf("after: %v", got)
	}
}

// TestFinishedHoursBuildTheNormal: an hour, once complete and flushed, is
// folded into both its hour-of-week slot and the recent normal, once.
func TestFinishedHoursBuildTheNormal(t *testing.T) {
	gdb := openDB(t)
	hour := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC) // a Monday
	cell := model.PathCell{NodeID: 1, Inbound: "in", ClientASN: 44244, Country: "IR", Region: "Tehran", Network: "tcp", SourceKind: "peer"}
	for _, region := range []string{"Tehran", "Isfahan"} {
		cell.Region = region
		row := model.PathHour{Hour: hour.Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 60, Authed: 50, FailedAuth: 6, EarlyClose: 5}}
		if err := gdb.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	c := &clock{hour.Add(time.Hour + 10*time.Minute)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	for range 2 {
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var got []detect.Baseline
	gdb.Order("slot").Find(&got)
	if len(got) != 2 || got[0].Slot != detect.RecentSlot || got[1].Slot != detect.SlotOf(hour) || got[1].Slot != 9 {
		t.Fatalf("baselines = %+v", got)
	}
	for _, b := range got {
		if b.N != 1 || b.MeanAuthed != 100 || b.MeanFail != 0.1 || b.MeanEarly != 0.1 {
			t.Fatalf("baseline = %+v, want both regions summed, once", b)
		}
	}
}

// TestARestartIsNotADrop: just after Insight starts, the window holds a few
// minutes, not fifteen; the rate is read over what it holds, so a path at its
// normal rate is not taken for one whose traffic dropped.
func TestARestartIsNotADrop(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	k := detect.Key{Node: 1, Inbound: "trojan", ASN: 58224, Network: "tcp"}
	normal(gdb, t, k) // 120 an hour
	if err := d.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		traffic(d, k, 9, 9, 0) // 108 an hour
		c.step(detect.BucketEvery)
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a path at its rate after a restart: %v", got)
	}
}

// run feeds one five-minute bucket and evaluates, n times.
func run(t *testing.T, d *detect.Detector, c *clock, n int, feed func()) {
	t.Helper()
	for range n {
		if feed != nil {
			feed()
		}
		c.step(detect.BucketEvery)
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

// TestABlockThatLastsStaysABlock: the hours a path is down in are not folded
// into its normal. Folded, the mean sank toward the blocked value and the
// variance grew until the block read as normal: path.recovered two hours and
// twenty minutes into a block still going on.
func TestABlockThatLastsStaysABlock(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	k := detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}
	other := detect.Key{Node: 2, Inbound: "vless", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	normal(gdb, t, other)
	cell := func(node uint) model.PathCell {
		return model.PathCell{NodeID: node, Inbound: "vless", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"}
	}
	for h := range 6 {
		hour := c.t.Truncate(time.Hour).Unix()
		run(t, d, c, 12, func() {
			traffic(d, k, 40, 1, 38)
			traffic(d, other, 11, 10, 0)
		})
		gdb.Create(&model.PathHour{Hour: hour, PathCell: cell(1), PathCounters: model.PathCounters{Accepted: 480, Authed: 12, FailedAuth: 456}})
		gdb.Create(&model.PathHour{Hour: hour, PathCell: cell(2), PathCounters: model.PathCounters{Accepted: 132, Authed: 120}})
		if got := kinds(t, gdb); len(got) != 1 || got[0] != detect.KindDegraded {
			t.Fatalf("hour %d of the block: alerts %v, want the one degraded", h+1, got)
		}
	}
	var b detect.Baseline
	gdb.Where("node_id = 1 AND slot = ?", detect.RecentSlot).First(&b)
	if b.MeanAuthed != 120 || b.N != 24 {
		t.Fatalf("the blocked path's normal moved: %+v", b)
	}
	var healthy detect.Baseline
	gdb.Where("node_id = 2 AND slot = ?", detect.RecentSlot).First(&healthy)
	if healthy.N <= 24 {
		t.Fatalf("the healthy path's normal did not learn: %+v", healthy)
	}
	if !d.Degraded()[k] {
		t.Fatal("the path is no longer degraded")
	}
}

// TestARestartKeepsWhatIsDown: a degraded path is not alerted again by the
// process that starts after it, and its recovery is still said.
func TestARestartKeepsWhatIsDown(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	k := detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}
	other := detect.Key{Node: 2, Inbound: "vless", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	normal(gdb, t, other)
	bad := func(d *detect.Detector) func() {
		return func() { traffic(d, k, 40, 1, 38); traffic(d, other, 11, 10, 0) }
	}
	run(t, d, c, 4, bad(d))
	if got := kinds(t, gdb); len(got) != 1 || got[0] != detect.KindDegraded {
		t.Fatalf("before the restart: %v", got)
	}
	again := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	run(t, again, c, 6, bad(again))
	if got := kinds(t, gdb); len(got) != 1 {
		t.Fatalf("after the restart, still blocked: %v", got)
	}
	if !again.Degraded()[k] {
		t.Fatal("the restart forgot the path is down")
	}
	run(t, again, c, 6, func() { traffic(again, k, 11, 10, 0); traffic(again, other, 11, 10, 0) })
	if got := kinds(t, gdb); len(got) != 2 || got[1] != detect.KindRecovered {
		t.Fatalf("after it cleared: %v", got)
	}
	var left int64
	gdb.Model(&detect.PathState{}).Count(&left)
	if left != 0 {
		t.Fatalf("%d states left after the recovery", left)
	}
}

// TestNoDataIsNotNoTraffic: while the panel cannot be polled nothing is
// judged, and when the feed is back the window starts again — a panel
// restart must not read as every path dropping and every network cut off.
func TestNoDataIsNotNoTraffic(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now}
	keys := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"},
	}
	for _, k := range keys {
		normal(gdb, t, k)
	}
	feed := func() {
		d.Covered(nil)
		for _, k := range keys {
			traffic(d, k, 11, 10, 0)
		}
	}
	run(t, d, c, 6, feed)
	run(t, d, c, 8, d.Lost) // forty minutes of failed polls
	run(t, d, c, 6, feed)
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a broken feed raised %v", got)
	}
	// A node that is switched off sends nothing either, and that is not a
	// block of its paths.
	run(t, d, c, 6, func() {
		d.Covered(map[uint]bool{1: true}) // node 2 is not counting
		traffic(d, keys[0], 11, 10, 0)
	})
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a node that is off raised %v", got)
	}
}

// TestTheRestIsNotANetwork: ASN 0 is whatever had no network of its own in
// an hour. It has no normal, is never degraded and never "cut off".
func TestTheRestIsNotANetwork(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	for _, node := range []uint{1, 2} {
		normal(gdb, t, detect.Key{Node: node, Inbound: "a", ASN: detect.OtherASN, Network: "tcp"})
	}
	run(t, d, c, 6, nil)
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("ASN 0 raised %v", got)
	}
}

// TestAQuietPathIsNotADrop: a path whose normal expects a handful of
// sessions in the window is not judged a drop for having none.
func TestAQuietPathIsNotADrop(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	b := detect.Baseline{NodeID: 1, Inbound: "a", ASN: 44244, Network: "tcp", Slot: detect.RecentSlot, N: 24, MeanAuthed: 24, VarAuthed: 4}
	if err := gdb.Create(&b).Error; err != nil {
		t.Fatal(err)
	}
	run(t, d, c, 6, nil)
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a quiet path raised %v", got)
	}
}

// TestAnOutageThatEndsSaysWhatIsStillDown: the paths of a network that came
// back, all but one, were never alerted while the outage spoke for them; the
// one still down is said when the outage ends.
func TestAnOutageThatEndsSaysWhatIsStillDown(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	keys := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 1, Inbound: "b", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"},
	}
	for _, k := range keys {
		normal(gdb, t, k)
	}
	run(t, d, c, 6, nil)
	run(t, d, c, 8, func() {
		traffic(d, keys[1], 11, 10, 0)
		traffic(d, keys[2], 11, 10, 0)
	})
	got := kinds(t, gdb)
	if len(got) != 3 || got[0] != detect.KindOutage || got[1] != detect.KindOutageEnd || got[2] != detect.KindDegraded {
		t.Fatalf("alerts = %v, want the outage, its end, and the path still down", got)
	}
}

// TestNodesGoingOffDoNotEndAnOutage: with a network cut off and its nodes
// then unreachable for an evaluation, its paths are not judged — and that is
// not the outage ending.
func TestNodesGoingOffDoNotEndAnOutage(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	for _, node := range []uint{1, 2} {
		normal(gdb, t, detect.Key{Node: node, Inbound: "a", ASN: 44244, Network: "tcp"})
	}
	run(t, d, c, 6, nil)
	run(t, d, c, 3, func() { d.Covered(map[uint]bool{}) }) // neither counts
	run(t, d, c, 6, func() { d.Covered(map[uint]bool{1: true, 2: true}) })
	if got := kinds(t, gdb); len(got) != 1 || got[0] != detect.KindOutage || !d.Outages()[44244] {
		t.Fatalf("alerts = %v, outage %v", got, d.Outages())
	}
}

// TestAFailedPollLosesNoHour: the panel keeps a quarter of an hour for a
// reader that is late, so a poll that fails and works again a minute later
// lost nothing and its hour still teaches the normal; a feed broken for
// longer, or samples the panel says it dropped, do not.
func TestAFailedPollLosesNoHour(t *testing.T) {
	cell := model.PathCell{NodeID: 1, Inbound: "in", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"}
	for name, breakFeed := range map[string]func(d *detect.Detector, c *clock){
		"a failed poll": func(d *detect.Detector, c *clock) {
			d.Lost()
			c.step(time.Minute)
			d.Covered(nil)
		},
		"a long break": func(d *detect.Detector, c *clock) {
			d.Lost()
			c.step(20 * time.Minute)
			d.Covered(nil)
		},
		"a gap": func(d *detect.Detector, _ *clock) { d.Gapped(); d.Covered(nil) },
	} {
		gdb := openDB(t)
		gdb.Where("1 = 1").Delete(&detect.Baseline{})
		gdb.Where("1 = 1").Delete(&model.PathHour{})
		gdb.Where("1 = 1").Delete(&model.State{})
		hour := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
		c := &clock{hour.Add(10 * time.Minute)}
		d := &detect.Detector{DB: gdb, Now: c.now}
		d.Covered(nil)
		if err := d.Evaluate(t.Context()); err != nil { // the fold's starting point
			t.Fatal(err)
		}
		c.step(20 * time.Minute)
		breakFeed(d, c)
		gdb.Create(&model.PathHour{Hour: hour.Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 60, Authed: 50}})
		c.t = hour.Add(time.Hour + 10*time.Minute)
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
		var n int64
		gdb.Model(&detect.Baseline{}).Count(&n)
		if want := name == "a failed poll"; (n > 0) != want {
			t.Errorf("%s: the hour was learned = %v, want %v", name, n > 0, want)
		}
	}
}

// TestPruneForgetsOnlyWhatIsGone: a path with no stored hour loses its
// normals and an endpoint with none its probe history — but not while no
// hour is being stored at all, when everything would look gone.
func TestPruneForgetsOnlyWhatIsGone(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now}
	live := detect.Key{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"}
	gone := detect.Key{Node: 9, Inbound: "old", ASN: 44244, Network: "tcp"}
	normal(gdb, t, live)
	normal(gdb, t, gone)
	gdb.Create(&detect.Suspicion{NodeID: 9, Inbound: "old", ProbedAtUnix: 1})
	gdb.Create(&detect.Suspicion{NodeID: 1, Inbound: "a", ProbedAtUnix: 1})
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, At: c.t.Add(-100 * 24 * time.Hour).Unix()})
	count := func() (baselines, suspicions, alerts int64) {
		gdb.Model(&detect.Baseline{}).Count(&baselines)
		gdb.Model(&detect.Suspicion{}).Count(&suspicions)
		gdb.Model(&detect.Alert{}).Count(&alerts)
		return
	}
	if err := d.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, s, a := count(); b != 2 || s != 2 || a != 0 {
		t.Fatalf("with no hour stored: %d normals, %d endpoints, %d alerts; want everything but the old alert kept", b, s, a)
	}
	cell := model.PathCell{NodeID: 1, Inbound: "a", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"}
	// A day of hours, but not yet a week of them since the feed came back:
	// still nothing is pruned.
	gdb.Create(&model.PathHour{Hour: c.t.Add(-time.Hour).Truncate(time.Hour).Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 5}})
	if err := d.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, s, _ := count(); b != 2 || s != 2 {
		t.Fatalf("within a week of the feed coming back: %d normals, %d endpoints", b, s)
	}
	// Six and a half days back is not yet the week.
	gdb.Create(&model.PathHour{Hour: c.t.Add(-156 * time.Hour).Truncate(time.Hour).Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 5}})
	if err := d.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b, s, _ := count(); b != 2 || s != 2 {
		t.Fatalf("six and a half days after the feed came back: %d normals, %d endpoints", b, s)
	}
	gdb.Create(&model.PathHour{Hour: c.t.Add(-7 * 24 * time.Hour).Truncate(time.Hour).Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 5}})
	if err := d.Prune(t.Context()); err != nil {
		t.Fatal(err)
	}
	var left []detect.Baseline
	gdb.Find(&left)
	if b, s, _ := count(); b != 1 || s != 1 || left[0].NodeID != 1 {
		t.Fatalf("after: %d normals, %d endpoints, %+v", b, s, left)
	}
}

// TestADeletedNodeIsNotCounting: a node the panel no longer lists — deleted
// after it went off — is not counting; its silence is no drop.
func TestADeletedNodeIsNotCounting(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now}
	keys := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"},
	}
	for _, k := range keys {
		normal(gdb, t, k)
	}
	both := func() {
		d.Covered(map[uint]bool{1: true, 2: true})
		traffic(d, keys[0], 11, 10, 0)
		traffic(d, keys[1], 11, 10, 0)
	}
	run(t, d, c, 6, both)
	run(t, d, c, 4, func() { d.Covered(map[uint]bool{1: true}); traffic(d, keys[0], 11, 10, 0) }) // off, listed as unknown
	run(t, d, c, 8, func() { d.Covered(map[uint]bool{1: true}); traffic(d, keys[0], 11, 10, 0) }) // deleted: not listed at all
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a deleted node raised %v", got)
	}
}

// TestAShortRestartBlindsNothing: a stop shorter than the panel keeps loses
// no sample, so its hours still teach the normals.
func TestAShortRestartBlindsNothing(t *testing.T) {
	gdb := openDB(t)
	hour := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	cell := model.PathCell{NodeID: 1, Inbound: "in", ClientASN: 44244, Country: "IR", Network: "tcp", SourceKind: "peer"}
	c := &clock{hour.Add(20 * time.Minute)}
	before := &detect.Detector{DB: gdb, Now: c.now}
	before.Covered(nil)
	if err := before.Evaluate(t.Context()); err != nil { // writes when the feed last worked
		t.Fatal(err)
	}
	c.step(4 * time.Minute) // the last poll before the stop, unrecorded
	c.step(6 * time.Minute) // the stop
	after := &detect.Detector{DB: gdb, Now: c.now}
	after.Covered(nil)
	gdb.Create(&model.PathHour{Hour: hour.Unix(), PathCell: cell, PathCounters: model.PathCounters{Accepted: 60, Authed: 50}})
	c.t = hour.Add(time.Hour + 10*time.Minute)
	after.Covered(nil)
	if err := after.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	var n int64
	gdb.Model(&detect.Baseline{}).Count(&n)
	if n == 0 {
		t.Fatal("a ten-minute restart kept its hour from the normals")
	}
}

// TestABrokenTunnelSpeaksForItsRelay:
// with a relay's tunnel down, every network failing on that relay raises no
// path.degraded and no asn.outage — the tunnel's own alert says it — while
// the paths still read degraded for the hints; a path still down once the
// tunnel is back is said then, and one that came back with it says nothing.
func TestABrokenTunnelSpeaksForItsRelay(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	down := map[uint]bool{1: true}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t, TunnelDown: func() map[uint]bool { return down }}
	relay := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 1, Inbound: "a", ASN: 58224, Network: "tcp"},
		{Node: 1, Inbound: "b", ASN: 44244, Network: "tcp"},
	}
	other := detect.Key{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"}
	for _, k := range append(relay, other) {
		normal(gdb, t, k)
	}
	eval := func(working map[detect.Key]bool) {
		t.Helper()
		for range detect.Buckets {
			for _, k := range append(relay, other) {
				if working[k] {
					traffic(d, k, 11, 10, 0)
				}
			}
			c.step(detect.BucketEvery)
		}
		if err := d.Evaluate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// Every network on the relay drops; the other node is fine.
	cut := map[detect.Key]bool{other: true}
	eval(cut)
	eval(cut)
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a broken tunnel raised %v", got)
	}
	for _, k := range relay {
		if !d.Degraded()[k] {
			t.Fatalf("%v is not degraded: the hints would keep its users on it", k)
		}
	}
	// The tunnel comes back; one path stays down (its inbound is blocked
	// too), the others work again. An evaluation whose window still holds
	// the cut says nothing of any of them.
	down = map[uint]bool{}
	healed := map[detect.Key]bool{other: true, relay[1]: true, relay[2]: true}
	for range detect.Buckets - 1 {
		for _, k := range []detect.Key{other, relay[1], relay[2]} {
			traffic(d, k, 11, 10, 0)
		}
		c.step(detect.BucketEvery)
	}
	if err := d.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := kinds(t, gdb); len(got) != 0 {
		t.Fatalf("a window still full of the cut spoke: %v", got)
	}
	eval(healed)
	got := kinds(t, gdb)
	if len(got) != 1 || got[0] != detect.KindDegraded {
		t.Fatalf("after the tunnel came back: %v", got)
	}
	var a detect.Alert
	gdb.First(&a)
	if a.NodeID != 1 || a.Inbound != "a" || a.ASN != 44244 {
		t.Fatalf("said %+v, want the path still down", a)
	}
	eval(healed)
	if got := kinds(t, gdb); len(got) != 1 {
		t.Fatalf("the paths that came back with the tunnel said something: %v", got)
	}
}

// stored writes path states as a stopped run leaves them.
func stored(t *testing.T, gdb *gorm.DB, rows ...detect.PathState) {
	t.Helper()
	for _, r := range rows {
		if err := gdb.Create(&r).Error; err != nil {
			t.Fatal(err)
		}
	}
}

// readings collects what d hands over.
func readings(d *detect.Detector) *[]detect.Reading {
	var out []detect.Reading
	d.OnRead = func(_ context.Context, r detect.Reading) { out = append(out, r) }
	return &out
}

func lastReading(t *testing.T, rs *[]detect.Reading) detect.Reading {
	t.Helper()
	if len(*rs) == 0 {
		t.Fatal("nothing handed over")
	}
	return (*rs)[len(*rs)-1]
}

// TestAReadingCarriesOnlyThisFeedsEvidence: an evaluation that judged hands
// over what it found; a path or an outage the last run stored, or one from
// before a break in the feed, is not in it until a window reads it bad
// again, though the detector keeps it; nothing is handed over unjudged; a
// path with a normal is judged with no traffic at all.
func TestAReadingCarriesOnlyThisFeedsEvidence(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	k := detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}
	other := detect.Key{Node: 2, Inbound: "vless", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	normal(gdb, t, other)
	stored(t, gdb,
		detect.PathState{NodeID: 1, Inbound: "vless", ASN: 44244, Network: "tcp", Alerted: true, Reason: "failures", Since: 1},
		detect.PathState{NodeID: 2, Inbound: "vless", ASN: 44244, Network: "tcp", Alerted: true, Reason: "failures", Since: 1},
		detect.PathState{ASN: 44244, Since: 1},
	)
	d := &detect.Detector{DB: gdb, Now: c.now}
	rs := readings(d)
	// Not fed, then fed for under a bucket: nothing judged, nothing handed.
	run(t, d, c, 1, nil)
	d.Covered(nil)
	c.step(detect.BucketEvery - time.Second)
	if err := d.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(*rs) != 0 {
		t.Fatalf("handed over %d readings unjudged", len(*rs))
	}
	healthy := func() { traffic(d, k, 11, 10, 0); traffic(d, other, 11, 10, 0) }
	bad := func() { traffic(d, k, 40, 1, 38); traffic(d, other, 40, 1, 38) }
	c.step(time.Second)
	healthy()
	if err := d.Evaluate(t.Context()); err != nil {
		t.Fatal(err)
	}
	last := lastReading(t, rs)
	if !d.Degraded()[k] || !d.Outages()[44244] {
		t.Fatal("one good window cleared what the last run stored")
	}
	if len(last.Degraded) != 0 || len(last.Outages) != 0 || !last.Judged[k] || !last.Judged[other] || !last.At.Equal(c.t) {
		t.Fatalf("reading after the restart = %+v", last)
	}
	run(t, d, c, 1, bad)
	if last = lastReading(t, rs); !last.Degraded[k] || !last.Degraded[other] || !last.Outages[44244] {
		t.Fatalf("read bad again = %+v", last)
	}
	// A break in the feed, or a gap in the panel's buffer: what was read
	// before it is not this feed's.
	for _, brk := range []func(){d.Lost, d.Gapped} {
		run(t, d, c, 1, bad)
		brk()
		d.Covered(nil)
		run(t, d, c, 1, healthy)
		if last = lastReading(t, rs); len(last.Degraded) != 0 || len(last.Outages) != 0 {
			t.Fatalf("reading after a break = %+v", last)
		}
	}
	// No traffic at all, a window of it: still judged, and bad.
	run(t, d, c, detect.Buckets+1, nil)
	if last = lastReading(t, rs); !last.Judged[k] || !last.Degraded[k] {
		t.Fatalf("reading of a silent path = %+v", last)
	}
}

// TestAReadingsOutageNeedsItsOwnStart: an outage the detector holds from
// the last run is in a reading only once this feed reads every path of it
// bad on two nodes; one bad and one good is not one.
func TestAReadingsOutageNeedsItsOwnStart(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	k := detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}
	other := detect.Key{Node: 2, Inbound: "vless", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	normal(gdb, t, other)
	stored(t, gdb,
		detect.PathState{NodeID: 1, Inbound: "vless", ASN: 44244, Network: "tcp", Since: 1},
		detect.PathState{NodeID: 2, Inbound: "vless", ASN: 44244, Network: "tcp", Since: 1},
		detect.PathState{ASN: 44244, Since: 1},
	)
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	rs := readings(d)
	run(t, d, c, 1, func() { traffic(d, k, 40, 1, 38); traffic(d, other, 11, 10, 0) })
	last := lastReading(t, rs)
	if !d.Outages()[44244] || !last.Degraded[k] || last.Degraded[other] || len(last.Outages) != 0 {
		t.Fatalf("detector outage %v, reading %+v", d.Outages(), last)
	}
}

// TestAReadingsOutageStaysAtHalf: once a reading holds an outage it stays
// while half its judged paths read bad, as the detector's own does.
func TestAReadingsOutageStaysAtHalf(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	keys := []detect.Key{
		{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 1, Inbound: "b", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"},
		{Node: 2, Inbound: "b", ASN: 44244, Network: "tcp"},
	}
	for _, k := range keys {
		normal(gdb, t, k)
	}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	rs := readings(d)
	feed := func(good int) func() {
		return func() {
			for i, k := range keys {
				if i < good {
					traffic(d, k, 11, 10, 0)
				} else {
					traffic(d, k, 40, 1, 38)
				}
			}
		}
	}
	run(t, d, c, 2, feed(0))
	if last := lastReading(t, rs); !last.Outages[44244] {
		t.Fatalf("whole ASN bad: %+v", last)
	}
	run(t, d, c, detect.Buckets+2, feed(2))
	last := lastReading(t, rs)
	if !d.Outages()[44244] || !last.Outages[44244] || len(last.Degraded) != 2 {
		t.Fatalf("half back: detector %v, reading %+v", d.Outages(), last)
	}
}

// TestAReadingLeavesOutWhatWasNotJudged: a path too quiet to judge, or on a
// relay a broken tunnel explains (and for a window after), is not in a
// reading, whatever its state.
func TestAReadingLeavesOutWhatWasNotJudged(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	quiet := detect.Key{Node: 1, Inbound: "a", ASN: 44244, Network: "tcp"}
	relay := detect.Key{Node: 2, Inbound: "a", ASN: 44244, Network: "tcp"}
	if err := gdb.Create(&detect.Baseline{NodeID: 1, Inbound: "a", ASN: 44244, Network: "tcp", Slot: detect.RecentSlot, N: 24, MeanAuthed: 4, VarAuthed: 4}).Error; err != nil {
		t.Fatal(err)
	}
	normal(gdb, t, relay)
	stored(t, gdb, detect.PathState{NodeID: 1, Inbound: "a", ASN: 44244, Network: "tcp", Since: 1})
	cut := true
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t, TunnelDown: func() map[uint]bool {
		if cut {
			return map[uint]bool{2: true}
		}
		return nil
	}}
	rs := readings(d)
	run(t, d, c, 2, func() { traffic(d, relay, 40, 1, 38) })
	if last := lastReading(t, rs); len(last.Judged) != 0 || len(last.Degraded) != 0 {
		t.Fatalf("tunnel down: %+v", last)
	}
	cut = false
	run(t, d, c, detect.Buckets-1, func() { traffic(d, relay, 40, 1, 38) })
	if last := lastReading(t, rs); len(last.Judged) != 0 {
		t.Fatalf("tunnel back under a window: %+v", last)
	}
	run(t, d, c, 2, func() { traffic(d, relay, 40, 1, 38) })
	if last := lastReading(t, rs); !last.Judged[relay] || last.Judged[quiet] || !last.Degraded[relay] || len(last.Degraded) != 1 {
		t.Fatalf("tunnel back a window: %+v", last)
	}
}

// TestAFailedStoreHandsNothingOver: an evaluation whose states and alerts
// could not be stored hands no reading over.
func TestAFailedStoreHandsNothingOver(t *testing.T) {
	gdb := openDB(t)
	c := &clock{time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	k := detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}
	normal(gdb, t, k)
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	rs := readings(d)
	run(t, d, c, 1, func() { traffic(d, k, 40, 1, 38) })
	n := len(*rs)
	refuse := errors.New("refused")
	if err := gdb.Callback().Create().Before("gorm:create").Register("refuse_alerts", func(tx *gorm.DB) {
		if tx.Statement.Table == "alerts" {
			_ = tx.AddError(refuse)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gdb.Callback().Create().Remove("refuse_alerts") })
	traffic(d, k, 40, 1, 38)
	c.step(detect.BucketEvery)
	if err := d.Evaluate(t.Context()); !errors.Is(err, refuse) {
		t.Fatalf("the store answered %v", err)
	}
	if len(*rs) != n {
		t.Fatalf("handed over %d readings after a failed store", len(*rs)-n)
	}
}
