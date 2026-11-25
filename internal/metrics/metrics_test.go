package metrics_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/metrics"
	"github.com/nx-panel/insight/internal/model"
)

func scrape(t *testing.T, h http.HandlerFunc, auth string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.String()
}

// TestMetricsNeedTheirToken: no token configured is no route; a wrong or
// missing bearer is refused.
func TestMetricsNeedTheirToken(t *testing.T) {
	if code, _ := scrape(t, metrics.Handler(func() string { return "" }, metrics.Sources{}), "Bearer "); code != http.StatusNotFound {
		t.Fatalf("no token configured = %d, want 404", code)
	}
	h := metrics.Handler(func() string { return "a-token-long-enough" }, metrics.Sources{})
	for _, auth := range []string{"", "Bearer wrong", "a-token-long-enough", "Bearer a-token-long-enough "} {
		if code, _ := scrape(t, h, auth); code != http.StatusUnauthorized {
			t.Errorf("%q = %d, want 401", auth, code)
		}
	}
	if code, _ := scrape(t, h, "Bearer a-token-long-enough"); code != http.StatusOK {
		t.Fatalf("the right token = %d", code)
	}
}

// TestMetricsAreBounded: forty client networks on one inbound
// make MaxASNs series of their own and one "other", never a prefix or an
// address; the detector's paths, the names and the alert counts are there,
// and every line parses as the exposition format.
func TestMetricsAreBounded(t *testing.T) {
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	d := &detect.Detector{DB: gdb, Now: func() time.Time { return now }}
	for i := range 40 {
		// The busiest first: ASN 64600 has the most.
		d.Observe(detect.Key{Node: 1, Inbound: "vless", ASN: uint32(64600 + i), Network: "tcp"},
			model.PathCounters{Accepted: uint64(100 - i), Authed: uint64(90 - i), FailedAuth: 3, EarlyClose: 1})
	}
	d.Observe(detect.Key{Node: 1, Inbound: "vless", ASN: 64600, Network: "udp"}, model.PathCounters{Accepted: 5, Authed: 5})
	gdb.Create(&model.NodeNetinfo{NodeID: 1, Name: `fsn "1"`})
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, At: now.Add(-time.Hour).Unix()})
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, At: now.Add(-30 * time.Hour).Unix()})
	gdb.Create(&detect.Suspicion{NodeID: 1, Inbound: "vless", Score: 60})

	var b strings.Builder
	src := metrics.Sources{DB: gdb, Detect: d, Org: func(a uint32) string {
		if a == 64600 {
			return "MCI"
		}
		return ""
	}, Now: func() time.Time { return now }}
	if err := metrics.Write(t.Context(), &b, src); err != nil {
		t.Fatal(err)
	}
	text := b.String()
	line := regexp.MustCompile(`^[a-z_][a-z0-9_]*(\{([a-z_]+="([^"\\]|\\.)*",?)*\})? -?[0-9.e+]+$`)
	accepted := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		if !line.MatchString(l) {
			t.Errorf("not the exposition format: %q", l)
		}
		if strings.HasPrefix(l, "insight_path_accepted_15m{") {
			asn := regexp.MustCompile(`asn="([^"]*)"`).FindStringSubmatch(l)[1]
			accepted[asn]++
		}
	}
	if len(accepted) != metrics.MaxASNs+1 || accepted[metrics.Other] != 1 {
		t.Fatalf("path series by asn = %v, want %d networks and one other", accepted, metrics.MaxASNs)
	}
	if accepted["64600"] != 2 {
		t.Fatalf("AS64600 has %d series, want tcp and udp", accepted["64600"])
	}
	for _, want := range []string{
		`insight_path_accepted_15m{node="fsn \"1\"",node_id="1",inbound="vless",kind="inbound",asn="64600",org="MCI",network="tcp"} 100`,
		`insight_alerts_24h{kind="path.degraded"} 1`,
		`insight_probe_score{node="fsn \"1\"",node_id="1",inbound="vless"} 60`,
		`insight_paths_degraded 0`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
	// What the other line folds: the thirty busiest past the ten.
	var otherSum int
	for i := metrics.MaxASNs; i < 40; i++ {
		otherSum += 100 - i
	}
	if !strings.Contains(text, `asn="other",org="",network="tcp"} `+strconv.Itoa(otherSum)) {
		t.Errorf("the other series is not the sum of the rest (%d):\n%s", otherSum, text)
	}
	if regexp.MustCompile(`\d+\.\d+\.\d+\.\d+|/24|/48`).MatchString(text) {
		t.Fatal("an address or a prefix in the metrics")
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

// TestOnlyAWireGuardPathIsLabelledEndpoint: a WireGuard endpoint counts
// only handshakes and is kind="endpoint"; an OpenVPN or OpenConnect
// endpoint counts like an inbound and is kind="inbound", so the
// dashboard's success ratio over the inbounds keeps it.
func TestOnlyAWireGuardPathIsLabelledEndpoint(t *testing.T) {
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(t.TempDir(), "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	in := &ingest.Ingest{DB: gdb, Now: func() time.Time { return now }, Panel: func() ingest.Getter {
		return shapesPanel{{ID: 1, State: ingest.StateNodeOn, Inbounds: []ingest.Shape{
			{Tag: "wg", Kind: ingest.KindEndpoint, Type: "wireguard"},
			{Tag: "ovpn", Kind: ingest.KindEndpoint, Type: "openvpn-server"},
			{Tag: "ocserv", Kind: ingest.KindEndpoint, Type: "openconnect-server"},
		}}}
	}}
	if err := in.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	d := &detect.Detector{DB: gdb, Now: func() time.Time { return now }}
	d.Observe(detect.Key{Node: 1, Inbound: "wg", ASN: 64600, Network: "udp"}, model.PathCounters{Authed: 10})
	d.Observe(detect.Key{Node: 1, Inbound: "ovpn", ASN: 64600, Network: "tcp"}, model.PathCounters{Accepted: 100, Authed: 10, FailedAuth: 90})
	d.Observe(detect.Key{Node: 1, Inbound: "ocserv", ASN: 64600, Network: "tcp"}, model.PathCounters{Accepted: 20, Authed: 20})
	var b strings.Builder
	if err := metrics.Write(t.Context(), &b, metrics.Sources{DB: gdb, Detect: d, Ingest: in, Now: func() time.Time { return now }}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`insight_path_authed_15m{node="#1",node_id="1",inbound="wg",kind="endpoint",`,
		`insight_path_failed_15m{node="#1",node_id="1",inbound="ovpn",kind="inbound",`,
		`insight_path_accepted_15m{node="#1",node_id="1",inbound="ocserv",kind="inbound",`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %s in\n%s", want, b.String())
		}
	}
}
