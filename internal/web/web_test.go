package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/insight/internal/admins"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"gorm.io/gorm"
)

const manifest = `{"api":1,"slug":"insight","name":"NX Insight","version":"0.1.0","scopes":[{"scope":"telemetry:read","purpose":"x"}],"setup":"/nx/setup","health":"/health"}`

type env struct {
	t    *testing.T
	db   *gorm.DB
	srv  *httptest.Server
	http *http.Client
	det  *detect.Detector
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(dir, "i.db")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admins.EnsureFirst(gdb, "admin", "admin-secret-1"); err != nil {
		t.Fatal(err)
	}
	a, err := addon.New(addon.Config{Manifest: []byte(manifest), DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	asns, _ := netinfo.ReadASN(strings.NewReader("5.160.0.0\t5.160.255.255\t44244\tIR\tMCI\n"))
	net := &netinfo.DB{}
	net.SetASN(asns)
	det := &detect.Detector{DB: gdb}
	s := New(gdb, a, config.Config{}, "0.1.0", nil, Parts{Detect: det, Net: net})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &env{t: t, db: gdb, srv: srv, http: &http.Client{Jar: jar}, det: det}
}

func (e *env) call(method, path string, body, out any) int {
	e.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", e.srv.URL)
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

// TestTheAdminWebNeedsASignIn: every data route is refused without a
// session and answered with one.
func TestTheAdminWebNeedsASignIn(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/status", "/api/matrix", "/api/nodes", "/api/alerts", "/api/suggestions"} {
		if code := e.call("GET", p, nil, nil); code != http.StatusUnauthorized {
			t.Errorf("signed out GET %s = %d", p, code)
		}
	}
	if code := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "wrong-one-1"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("a wrong password = %d", code)
	}
	if code := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil); code != http.StatusOK {
		t.Fatalf("sign in = %d", code)
	}
	for _, p := range []string{"/api/status", "/api/matrix", "/api/nodes", "/api/alerts", "/api/suggestions"} {
		if code := e.call("GET", p, nil, nil); code != http.StatusOK {
			t.Errorf("signed in GET %s = %d", p, code)
		}
	}
}

// TestTheMatrixAndTheNodes: the matrix sums the window's cells per client
// network, node and inbound with the ASN's name and the RTT; an override is
// saved and read back through the effective network.
func TestTheMatrixAndTheNodes(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	hour := time.Now().Truncate(time.Hour).Unix()
	for _, region := range []string{"Tehran", "Isfahan"} {
		row := model.PathHour{
			Hour: hour, PathCell: model.PathCell{NodeID: 1, Inbound: "vless", ClientASN: 44244, Country: "IR", Region: region, Network: "tcp", SourceKind: "peer"},
			PathCounters: model.PathCounters{Accepted: 10, Authed: 9, FailedAuth: 1, RTTSum: 150 * 9, RTTN: 9},
		}
		e.db.Create(&row)
	}
	e.db.Create(&model.NodeNetinfo{NodeID: 1, Name: "fsn", Address: "88.198.1.1", ASN: 24940, Org: "HETZNER", Country: "DE", City: "Falkenstein"})
	var m struct {
		Cells []cellView `json:"cells"`
		Nodes []nodeView `json:"nodes"`
	}
	if code := e.call("GET", "/api/matrix?hours=6", nil, &m); code != http.StatusOK {
		t.Fatalf("matrix = %d", code)
	}
	if len(m.Cells) != 1 || m.Cells[0].Accepted != 20 || m.Cells[0].Org != "MCI" || m.Cells[0].RTTMs != 150 || len(m.Nodes) != 1 {
		t.Fatalf("matrix = %+v", m)
	}
	if code := e.call("GET", "/api/matrix?hours=6&by=region", nil, &m); code != http.StatusOK || len(m.Cells) != 2 {
		t.Fatalf("by region = %d %+v", code, m.Cells)
	}
	if code := e.call("GET", "/api/matrix?hours=999", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("a window past a week = %d", code)
	}
	var n nodeView
	if code := e.call("PUT", "/api/nodes/1/override", map[string]any{"asn": 0, "org": "", "country": "de", "city": "Nuremberg"}, &n); code != http.StatusOK {
		t.Fatalf("override = %d", code)
	}
	if n.Effective.City != "Nuremberg" || n.Effective.Country != "DE" || n.Effective.Org != "HETZNER" {
		t.Fatalf("effective = %+v", n.Effective)
	}
	if code := e.call("PUT", "/api/nodes/1/override", map[string]any{"country": "DEU"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a three-letter country = %d", code)
	}
	if code := e.call("PUT", "/api/nodes/9/override", map[string]any{"city": "x"}, nil); code != http.StatusNotFound {
		t.Fatalf("an unknown node = %d", code)
	}
}

// TestAlertsNewestFirst: the list is newest first and pages by id.
func TestAlertsNewestFirst(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)
	for i := range 3 {
		e.db.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, ASN: 44244, At: int64(1000 + i)})
	}
	var got []struct {
		ID  uint   `json:"id"`
		Org string `json:"org"`
	}
	e.call("GET", "/api/alerts", nil, &got)
	if len(got) != 3 || got[0].ID != 3 || got[0].Org != "MCI" {
		t.Fatalf("alerts = %+v", got)
	}
	e.call("GET", "/api/alerts?before=2", nil, &got)
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("before 2 = %+v", got)
	}
}
