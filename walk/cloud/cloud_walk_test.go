//go:build cloudwalk

// The Mode B walk against the real cloud Worker and the real licence Worker
// under `wrangler dev` (run.sh starts both and seeds the contributors):
// five installs send their closed hour, the cloud stores the cells, NX
// publishes a report, and each install fetches it — the licensed ones in
// full, the free one disruption only — verified against the feed key
// built into Insight. The model call itself is not part of the walk: it
// needs Cloudflare's AI binding; run.sh writes a finished run in its place.
package cloud_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

// Seed is install i's key seed: run.sh derives the same public keys.
func Seed(i int) []byte {
	s := make([]byte, ed25519.SeedSize)
	copy(s, fmt.Sprintf("nx-insight-walk-install-%d", i))
	return s
}

// fakePanel takes the key as the panel does; the walk's licence Worker has
// the contributors seeded by run.sh instead of a heartbeat delivering them.
type fakePanel struct{}

func (fakePanel) Put(context.Context, string, any, any) error { return nil }
func (fakePanel) Delete(context.Context, string) error        { return nil }

type noState struct{}

func (noState) Degraded() map[detect.Key]bool { return nil }
func (noState) Outages() map[uint32]bool      { return nil }

func install(t *testing.T, i int, url string, hour int64, success uint64) *cloud.Cloud {
	t.Helper()
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "insight.db")})
	if err != nil {
		t.Fatal(err)
	}
	cells := []model.PathHour{
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: fmt.Sprintf("reality-%d", i), ClientASN: 197207, Country: "IR", Region: "Tehran", Network: "tcp"},
			PathCounters: model.PathCounters{Accepted: 100, Authed: success, FailedTLS: 100 - success, EarlyClose: 40, RTTSum: 150 * success, RTTN: success},
		},
		{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: fmt.Sprintf("xhttp-cdn-%d", i), ClientASN: 197207, Country: "IR", Region: "Tehran", Network: "tcp"},
			PathCounters: model.PathCounters{Accepted: 80, Authed: 4, FailedTLS: 76},
		},
	}
	must(t, gdb.Create(&cells).Error)
	must(t, gdb.Create(&model.NodeNetinfo{NodeID: 1, Name: fmt.Sprintf("node-%d", i), Address: "203.0.113.1", ASN: 24940, Org: "HETZNER-AS", Country: "DE"}).Error)
	must(t, model.PutState(gdb, "cloud_key", base64.StdEncoding.EncodeToString(Seed(i))))
	shapes := map[uint]map[string]ingest.Shape{1: {
		cells[0].Inbound: {Type: "vless", Transport: "none", Security: "reality"},
		cells[1].Inbound: {Type: "vless", Transport: "xhttp", Security: "tls", Fronted: true},
	}}
	return &cloud.Cloud{
		DB: gdb, URL: url,
		Sources: cloud.Sources{
			DB: gdb, State: noState{}, Version: "0.0.2",
			Shapes:  func() map[uint]map[string]ingest.Shape { return shapes },
			Tunnels: func() []tunnels.View { return nil },
			Org:     func(uint32) string { return "MCCI" },
		},
		Panel: func() cloud.Panel { return fakePanel{} },
		Now:   func() time.Time { return time.Unix(hour+3600+7*60, 0) },
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCloudWalk(t *testing.T) {
	url := os.Getenv("NX_CLOUD_WALK_URL")
	if url == "" {
		t.Skip("NX_CLOUD_WALK_URL is not set (walk/cloud/run.sh)")
	}
	now := time.Now().Unix()
	hour := now - now%3600 - 3600
	var installs []*cloud.Cloud
	for i := range 5 {
		c := install(t, i, url, hour, 95)
		installs = append(installs, c)
		// Consent an hour before the hour sent, so the hour is due.
		c.Now = func() time.Time { return time.Unix(hour-60, 0) }
		must(t, c.SetOn(t.Context(), true))
		c.Now = func() time.Time { return time.Now() }
		must(t, c.Tick(t.Context()))
		st, err := c.Status(t.Context())
		must(t, err)
		if st.LastSent == nil || st.LastSent.Hour != hour {
			t.Fatalf("install %d did not send its hour: %+v", i, st)
		}
	}
	// run.sh publishes once the cells are stored; it waits for this file.
	if dir := os.Getenv("NX_CLOUD_WALK_DIR"); dir != "" {
		must(t, os.WriteFile(filepath.Join(dir, "sent"), []byte(fmt.Sprint(hour)), 0o600))
		deadline := time.Now().Add(90 * time.Second)
		for {
			if _, err := os.Stat(filepath.Join(dir, "published")); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("run.sh did not publish")
			}
			time.Sleep(time.Second)
		}
	}
	for i, c := range installs {
		must(t, c.CheckReport(t.Context(), true))
		h := c.Held(t.Context())
		if h.Report == nil {
			t.Fatalf("install %d holds no report: %+v", i, h)
		}
		codes := []string{}
		for _, f := range h.Report.Countries[0].Findings {
			codes = append(codes, f.Code)
		}
		want := "full"
		if i == 4 {
			want = "disruption"
		}
		if h.Report.Tier != want {
			t.Errorf("install %d got the %s report, want %s (%v)", i, h.Report.Tier, want, codes)
		}
		t.Logf("install %d: %s report %d: %v", i, h.Report.Tier, h.Report.ExtractedAt, codes)
		// Asking again: the signal that there is nothing newer.
		must(t, c.CheckReport(t.Context(), true))
		if c.Held(t.Context()).Latest != h.Report.ExtractedAt {
			t.Errorf("install %d: the second answer named %d", i, c.Held(t.Context()).Latest)
		}
	}
}
