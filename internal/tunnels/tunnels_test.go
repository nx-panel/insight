package tunnels_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/tunnels"
)

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
		for _, m := range append(tunnels.Tables(), &detect.Alert{}) {
			gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m)
		}
	}
	return gdb
}

// fakePanel answers the two routes from a script.
type fakePanel struct {
	mu      sync.Mutex
	list    string
	healthy map[uint]bool
	relayUp map[uint]bool
	err     error
}

func (f *fakePanel) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if strings.HasPrefix(path, "/tunnels?") {
		return json.Unmarshal([]byte(f.list), out)
	}
	var id uint
	if _, err := fmt.Sscanf(path, "/tunnels/%d/status", &id); err != nil {
		return err
	}
	reach, ok := f.relayUp[id]
	if !ok {
		reach = true
	}
	body := fmt.Sprintf(`{"healthy":%v,"relay":{"nodeId":1,"nodeName":"ir-1","reachable":%v,"sessions":[]},"origins":[{"nodeId":2,"nodeName":"de-1","reachable":false}]}`, f.healthy[id], reach)
	return json.Unmarshal([]byte(body), out)
}

const twoTunnels = `{"items":[
	{"id":3,"name":"to-de","mode":"reverse","relayNodeId":1,"relayName":"ir-1","originIds":[2],"originNames":["de-1"]},
	{"id":4,"name":"off","enabled":false,"relayNodeId":5,"relayName":"ir-2","originIds":[2],"originNames":["de-1"]}
]}`

func alerts(t *testing.T, gdb *gorm.DB) []detect.Alert {
	t.Helper()
	var out []detect.Alert
	if err := gdb.Order("id").Find(&out).Error; err != nil {
		t.Fatal(err)
	}
	return out
}

// TestATunnelWithNoLinkIsDownAfterTwoPolls is PT16's watcher: a tunnel goes
// down after two polls with no link and comes back after two with one,
// each change one alert naming the tunnel and its relay; a relay the panel
// cannot reach says nothing; a disabled tunnel is never asked; a restart
// keeps the state without alerting again.
func TestATunnelWithNoLinkIsDownAfterTwoPolls(t *testing.T) {
	gdb := openDB(t)
	f := &fakePanel{list: twoTunnels, healthy: map[uint]bool{3: true}, relayUp: map[uint]bool{}}
	var sent []detect.Alert
	w := &tunnels.Watcher{DB: gdb, Panel: func() tunnels.Getter { return f }, Send: func(_ context.Context, a detect.Alert) { sent = append(sent, a) }}
	ctx := context.Background()
	poll := func() {
		t.Helper()
		if err := w.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}

	poll()
	if v := w.Views(); len(v) != 2 || v[0].State != tunnels.Up || v[1].State != tunnels.Unknown || v[1].Enabled {
		t.Fatalf("views = %+v", v)
	}
	f.healthy[3] = false
	poll()
	if len(w.Down()) != 0 || len(sent) != 0 {
		t.Fatal("one poll with no link moved the state")
	}
	f.relayUp[3] = false
	poll() // the relay is unreachable: no evidence, the count holds
	f.relayUp[3] = true
	poll()
	if !w.Down()[1] || len(sent) != 1 {
		t.Fatalf("down = %v, sent = %+v", w.Down(), sent)
	}
	a := sent[0]
	if a.Kind != detect.KindTunnelDown || a.NodeID != 1 || a.Tunnel != "to-de" || !strings.Contains(a.Detail, `"unreachable":["de-1"]`) {
		t.Fatalf("alert = %+v", a)
	}
	if v := w.Views()[0]; v.State != tunnels.Down || v.Since == 0 || len(v.Unlinked) != 1 || v.Unlinked[0] != 2 {
		t.Fatalf("view = %+v", v)
	}

	// A restart remembers it is down and does not say it again.
	again := &tunnels.Watcher{DB: gdb, Panel: func() tunnels.Getter { return f }, Send: func(_ context.Context, a detect.Alert) { sent = append(sent, a) }}
	if err := again.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !again.Down()[1] || len(sent) != 1 {
		t.Fatalf("after a restart: down %v, sent %d", again.Down(), len(sent))
	}
	f.healthy[3] = true
	for range 2 {
		if err := again.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if len(again.Down()) != 0 || len(sent) != 2 || sent[1].Kind != detect.KindTunnelUp {
		t.Fatalf("back: down %v, sent %+v", again.Down(), sent)
	}
	if got := alerts(t, gdb); len(got) != 2 {
		t.Fatalf("stored alerts = %+v", got)
	}
	var rows int64
	gdb.Model(&tunnels.TunnelState{}).Count(&rows)
	if rows != 0 {
		t.Fatalf("%d state rows left for a tunnel that is up", rows)
	}
}

// TestADeletedOrDisabledTunnelIsForgottenSilently: a tunnel down when the
// operator switches it off, or deletes it, ends without an "up" alert.
func TestADeletedOrDisabledTunnelIsForgottenSilently(t *testing.T) {
	gdb := openDB(t)
	f := &fakePanel{list: twoTunnels, healthy: map[uint]bool{}, relayUp: map[uint]bool{}}
	var sent int
	w := &tunnels.Watcher{DB: gdb, Panel: func() tunnels.Getter { return f }, Send: func(context.Context, detect.Alert) { sent++ }, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	ctx := context.Background()
	for range 2 {
		if err := w.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if !w.Down()[1] || sent != 1 {
		t.Fatalf("down %v, sent %d", w.Down(), sent)
	}
	f.list = strings.Replace(twoTunnels, `"name":"to-de",`, `"name":"to-de","enabled":false,`, 1)
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.Down()) != 0 || sent != 1 {
		t.Fatalf("disabled: down %v, sent %d", w.Down(), sent)
	}
	f.list = `{"items":[]}`
	if err := w.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(w.Views()) != 0 || sent != 1 {
		t.Fatalf("deleted: views %+v, sent %d", w.Views(), sent)
	}
}
