package detect_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"gorm.io/gorm"
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

// TestABlockedPathAlertsAndRecovers is PT5's done_when on the detector: a
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

// TestAWholeASNDownIsOneOutage is P20 a: every path of a client ASN down on
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
// normal rate is not taken for one whose traffic dropped (found in the
// two-ASN walk, 2026-11-22).
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
