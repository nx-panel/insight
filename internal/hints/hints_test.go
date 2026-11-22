package hints

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

type fakeState struct {
	degraded map[detect.Key]bool
	outages  map[uint32]bool
}

func (f *fakeState) Degraded() map[detect.Key]bool { return f.degraded }
func (f *fakeState) Outages() map[uint32]bool      { return f.outages }

type fakePanel struct{ puts []Document }

func (f *fakePanel) Put(_ context.Context, path string, body any, _ any) error {
	f.puts = append(f.puts, body.(Document))
	return nil
}

func seed(t *testing.T, gdb *gorm.DB, hour int64, node uint, inbound string, asn uint32, accepted, authed uint64) {
	t.Helper()
	row := model.PathHour{
		Hour: hour, PathCell: model.PathCell{NodeID: node, Inbound: inbound, ClientASN: asn, Country: "IR", Network: "tcp", SourceKind: "peer"},
		PathCounters: model.PathCounters{Accepted: accepted, Authed: authed},
	}
	if err := gdb.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

// TestHintsFollowThePaths is PT5's done_when on the hints: for an ASN seen
// on two nodes, the node that works for it comes first and its working
// inbound first within it; a degraded path drops to the back; during the
// ASN's outage its group is left as it was; an unchanged document is not
// pushed again within the hour.
func TestHintsFollowThePaths(t *testing.T) {
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour).Unix()
	seed(t, gdb, hour, 1, "trojan", 44244, 100, 20) // node 1 is mostly blocked for MCI…
	seed(t, gdb, hour, 2, "vless", 44244, 100, 95)  // …node 2 works,
	seed(t, gdb, hour, 2, "trojan", 44244, 100, 60) // and its vless better than its trojan.
	seed(t, gdb, hour, 3, "vless", 58224, 100, 90)  // one node only for TCI: nothing to order.
	seed(t, gdb, hour, 1, "vless", 44244, 5, 5)     // too little to rank
	state := &fakeState{degraded: map[detect.Key]bool{}, outages: map[uint32]bool{}}
	fp := &fakePanel{}
	h := &Hints{
		DB: gdb, State: state, Now: func() time.Time { return now }, Panel: func() Putter { return fp },
		Prefixes: func(asns map[uint32]bool) map[uint32][]netip.Prefix {
			out := map[uint32][]netip.Prefix{}
			if asns[44244] {
				out[44244] = []netip.Prefix{netip.MustParsePrefix("5.160.0.0/16")}
			}
			return out
		},
	}
	if err := h.Push(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fp.puts) != 1 || len(fp.puts[0].Groups) != 1 {
		t.Fatalf("puts = %+v", fp.puts)
	}
	g := fp.puts[0].Groups[0]
	if g.CIDRs[0] != "5.160.0.0/16" || g.Order.Nodes[0] != 2 || g.Order.Nodes[1] != 1 ||
		g.Order.Inbounds["2"][0] != "vless" || g.Order.Inbounds["2"][1] != "trojan" || fp.puts[0].ExpiresAt != now.Add(Lifetime).Unix() {
		t.Fatalf("group = %+v", g)
	}

	if err := h.Push(t.Context()); err != nil || len(fp.puts) != 1 {
		t.Fatalf("an unchanged document was pushed again: %d, %v", len(fp.puts), err)
	}

	state.degraded[detect.Key{Node: 2, Inbound: "vless", ASN: 44244, Network: "tcp"}] = true
	state.degraded[detect.Key{Node: 2, Inbound: "trojan", ASN: 44244, Network: "tcp"}] = true
	if err := h.Push(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fp.puts) != 2 || fp.puts[1].Groups[0].Order.Nodes[0] != 1 {
		t.Fatalf("after node 2 was degraded: %+v", fp.puts[len(fp.puts)-1])
	}

	state.outages[44244] = true
	seed(t, gdb, hour-3600, 1, "vless", 44244, 200, 0) // the outage's numbers, which must not reorder
	before := fp.puts[1].Groups[0]
	doc, err := h.Compute(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 || doc.Groups[0].Order.Nodes[0] != before.Order.Nodes[0] {
		t.Fatalf("an outage reordered the ASN: %+v, was %+v", doc.Groups, before)
	}
}

// TestADeadPathStaysLastAndOrdersSettle: a degraded path with no traffic
// left in the window still ranks its node last — dropped, the network's
// group would vanish and the panel's default order come back exactly when
// the order matters; an outage keeps the group it had with no traffic at
// all; and two nodes a few points apart do not swap places every push.
func TestADeadPathStaysLastAndOrdersSettle(t *testing.T) {
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 12, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour).Unix()
	seed(t, gdb, hour, 2, "vless", 44244, 100, 95) // node 1 has no row: dead for the whole window
	state := &fakeState{degraded: map[detect.Key]bool{{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"}: true}, outages: map[uint32]bool{}}
	fp := &fakePanel{}
	h := &Hints{
		DB: gdb, State: state, Now: func() time.Time { return now }, Panel: func() Putter { return fp },
		Prefixes: func(map[uint32]bool) map[uint32][]netip.Prefix {
			return map[uint32][]netip.Prefix{44244: {netip.MustParsePrefix("5.160.0.0/16")}}
		},
	}
	if err := h.Push(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fp.puts) != 1 || len(fp.puts[0].Groups) != 1 || fmt.Sprint(fp.puts[0].Groups[0].Order.Nodes) != "[2 1]" {
		t.Fatalf("with node 1 dead: %+v", fp.puts)
	}
	// Node 1 is back and a little better than node 2: within the margin,
	// the pushed order stands.
	delete(state.degraded, detect.Key{Node: 1, Inbound: "vless", ASN: 44244, Network: "tcp"})
	seed(t, gdb, hour, 1, "vless", 44244, 100, 99)
	doc, err := h.Compute(t.Context())
	if err != nil || fmt.Sprint(doc.Groups[0].Order.Nodes) != "[2 1]" {
		t.Fatalf("four points apart reordered: %+v, %v", doc.Groups, err)
	}
	// Clearly better: it moves.
	seed(t, gdb, hour-3600, 2, "vless", 44244, 2000, 100)
	doc, err = h.Compute(t.Context())
	if err != nil || fmt.Sprint(doc.Groups[0].Order.Nodes) != "[1 2]" {
		t.Fatalf("a real difference did not reorder: %+v, %v", doc.Groups, err)
	}
	// The network is cut off and its hours age out of the window: its
	// group stays as pushed.
	state.outages[44244] = true
	gdb.Where("1 = 1").Delete(&model.PathHour{})
	doc, err = h.Compute(t.Context())
	if err != nil || len(doc.Groups) != 1 || fmt.Sprint(doc.Groups[0].Order.Nodes) != "[2 1]" {
		t.Fatalf("an outage with no traffic dropped or reordered the group: %+v, %v", doc.Groups, err)
	}
}

// TestSettleSeesEveryPair: steps of less than the margin between neighbours
// must not hide an order that is upside down end to end.
func TestSettleSeesEveryPair(t *testing.T) {
	scores := map[uint]float64{1: 0.60, 2: 0.69, 3: 0.78, 4: 0.87}
	got := settle([]uint{1, 2, 3, 4}, []uint{1, 2, 3, 4}, scores, func(a, b uint) bool { return a < b })
	if fmt.Sprint(got) != "[4 3 2 1]" {
		t.Fatalf("settle kept %v", got)
	}
	close := map[uint]float64{1: 0.90, 2: 0.93, 3: 0.96}
	if got := settle([]uint{1, 2, 3}, []uint{1, 2, 3}, close, func(a, b uint) bool { return a < b }); fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("within the margin reordered: %v", got)
	}
}

func TestClientPrefixBits(t *testing.T) {
	for addr, want := range map[string]int{"192.0.2.7": 24, "::ffff:192.0.2.7": 24, "2001:db8::1": 48, "2002:c000:207::1": 40} {
		if got := clientPrefixBits(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: /%d, want /%d", addr, got, want)
		}
	}
}
