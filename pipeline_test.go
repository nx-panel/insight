package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/hints"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/netinfo"
)

// panelStub is the panel as Insight sees it: the telemetry relay and the
// ordering document.
type panelStub struct {
	mu      sync.Mutex
	samples []ingest.Sample
	puts    []hints.Document
}

func (p *panelStub) Get(_ context.Context, path string, out any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var since uint64
	fmt.Sscanf(path[strings.Index(path, "since=")+6:], "%d", &since)
	page := map[string]any{"active": true, "cursor": since, "samples": []ingest.Sample{}}
	var got []ingest.Sample
	for _, s := range p.samples {
		if s.Cursor > since {
			got = append(got, s)
			page["cursor"] = s.Cursor
		}
	}
	page["samples"] = got
	raw, _ := json.Marshal(page)
	return json.Unmarshal(raw, out)
}

func (p *panelStub) Put(_ context.Context, _ string, body, _ any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.puts = append(p.puts, body.(hints.Document))
	return nil
}

// TestABlockedPathEndToEnd runs a block through the whole addon: two
// client networks (MCI and TCI as two fixture ASNs) reach two nodes;
// after a learning day MCI's handshakes to node 1 start failing — the path
// alerts within the window (two five-minute evaluations), MCI's hint puts
// node 2 first; when it clears, the path recovers and node 1 is back.
func TestABlockedPathEndToEnd(t *testing.T) {
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	asns, _ := netinfo.ReadASN(strings.NewReader("5.160.0.0\t5.160.255.255\t44244\tIR\tMCI\n2.176.0.0\t2.191.255.255\t58224\tIR\tTCI\n"))
	net := &netinfo.DB{}
	net.SetASN(asns)
	stub := &panelStub{}
	var alerts []detect.Alert
	in, det, hint := pipeline(gdb, net, func() ingest.Getter { return stub }, func(_ context.Context, a detect.Alert) { alerts = append(alerts, a) })
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	in.Now, det.Now, hint.Now = clock, clock, clock

	cursor := uint64(0)
	emit := func(node uint, prefix string, accepted, authed, failed uint32) {
		cursor++
		stub.mu.Lock()
		stub.samples = append(stub.samples, ingest.Sample{
			Cursor: cursor, NodeID: node, DateTime: now.Unix(), Inbound: "vless",
			Network: "tcp", Prefix: prefix, SourceKind: "peer", Accepted: accepted, Authed: authed, Failed: map[string]uint32{"auth": failed},
		})
		stub.mu.Unlock()
	}
	// Five minutes of the fleet: each client network on each node.
	tick := func(mciNode1Blocked bool) {
		t.Helper()
		if mciNode1Blocked {
			emit(1, "5.160.1.0/24", 40, 1, 38)
		} else {
			emit(1, "5.160.1.0/24", 11, 10, 0)
		}
		emit(2, "5.160.1.0/24", 11, 10, 0)
		emit(1, "2.176.1.0/24", 11, 10, 0)
		emit(2, "2.176.1.0/24", 11, 10, 0)
		if err := in.Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := in.Flush(t.Context()); err != nil {
			t.Fatal(err)
		}
		in.AfterFlush(t.Context())
		now = now.Add(ingest.FlushEvery)
	}
	for range 12 * 8 { // eight healthy hours teach the recent normal
		tick(false)
	}
	if len(alerts) != 0 {
		t.Fatalf("healthy hours raised %+v", alerts)
	}
	mciFirst := func() uint {
		stub.mu.Lock()
		defer stub.mu.Unlock()
		last := stub.puts[len(stub.puts)-1]
		for _, g := range last.Groups {
			if len(g.CIDRs) > 0 && g.CIDRs[0] == "5.160.0.0/16" {
				return g.Order.Nodes[0]
			}
		}
		return 0
	}
	before := len(alerts)
	for range 5 { // the window fills, then two bad evaluations
		tick(true)
	}
	if len(alerts) != before+1 || alerts[before].Kind != detect.KindDegraded || alerts[before].NodeID != 1 || alerts[before].ASN != 44244 {
		t.Fatalf("after the block: %+v", alerts[before:])
	}
	if got := mciFirst(); got != 2 {
		t.Fatalf("MCI's first node while node 1 is blocked = %d, want 2", got)
	}
	for range 5 {
		tick(false)
	}
	if last := alerts[len(alerts)-1]; last.Kind != detect.KindRecovered || last.NodeID != 1 {
		t.Fatalf("after it cleared: %+v", alerts[before:])
	}
}
