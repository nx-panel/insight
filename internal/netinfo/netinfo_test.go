package netinfo

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const asnFixture = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"5.160.0.0\t5.160.255.255\t44244\tIR\tIRANCELL-AS\n" +
	"10.0.0.0\t10.255.255.255\t0\tNone\tNot routed\n" +
	"2a01:4f8::\t2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff\t24940\tDE\tHETZNER-AS\n"

const cityFixture = "1.0.0.0,1.0.0.255,OC,AU,Queensland,\"South Brisbane\",-27.47,153.02\n" +
	"5.160.0.0,5.160.127.255,AS,IR,Isfahan,Isfahan,32.6,51.6\n" +
	"5.160.128.0,5.160.255.255,AS,IR,Tehran,Tehran,35.6,51.4\n" +
	"2a01:4f8::,2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff,EU,DE,Saxony,Falkenstein,50.4,12.3\n"

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestLookup(t *testing.T) {
	asn, err := ReadASN(bytes.NewReader(gz(t, asnFixture)))
	if err != nil {
		t.Fatal(err)
	}
	city, err := ReadCity(strings.NewReader(cityFixture), []string{"IR", "RU", "CN"})
	if err != nil {
		t.Fatal(err)
	}
	db := &DB{}
	db.SetASN(asn)
	db.SetCity(city)
	for addr, want := range map[string]Info{
		"5.160.10.1":        {ASN: 44244, Org: "IRANCELL-AS", Country: "IR", Region: "Isfahan", City: "Isfahan"},
		"5.160.200.9":       {ASN: 44244, Org: "IRANCELL-AS", Country: "IR", Region: "Tehran", City: "Tehran"},
		"1.0.0.7":           {ASN: 13335, Org: "CLOUDFLARENET", Country: "US"}, // AU kept out: not a region country
		"10.1.2.3":          {},                                                // not routed
		"2a01:4f8::1":       {ASN: 24940, Org: "HETZNER-AS", Country: "DE"},
		"::ffff:5.160.10.1": {ASN: 44244, Org: "IRANCELL-AS", Country: "IR", Region: "Isfahan", City: "Isfahan"},
	} {
		if got := db.Lookup(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %+v, want %+v", addr, got, want)
		}
	}
}

func TestScanCityFindsNodesAbroad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "city.csv.gz")
	if err := os.WriteFile(path, gz(t, cityFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanCity(path, []netip.Addr{netip.MustParseAddr("2a01:4f8::5"), netip.MustParseAddr("198.51.100.1")})
	if err != nil {
		t.Fatal(err)
	}
	if got[netip.MustParseAddr("2a01:4f8::5")].City != "Falkenstein" || len(got) != 1 {
		t.Fatalf("scan = %+v", got)
	}
}

// TestRefreshDownloadsAndFallsBackAMonth: both files are fetched into the
// directory and swapped in; a City Lite not published yet for this month is
// taken from the month before; a file that does not parse leaves the one in
// use alone.
func TestRefreshDownloadsAndFallsBackAMonth(t *testing.T) {
	now := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/asn.tsv.gz":
			w.Write(gz(t, asnFixture))
		case "/city-2026-10.csv.gz":
			w.Write(gz(t, cityFixture))
		case "/broken.tsv.gz":
			w.Write(gz(t, "not a range\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	m := &Manager{
		DB: &DB{}, Dir: t.TempDir(), Now: func() time.Time { return now },
		Sources: Sources{ASNURL: srv.URL + "/asn.tsv.gz", CityURL: srv.URL + "/city-{month}.csv.gz", RegionCountries: []string{"IR"}},
	}
	if err := m.RefreshASN(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.RefreshCity(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := m.DB.Lookup(netip.MustParseAddr("5.160.10.1")); got.ASN != 44244 || got.Region != "Isfahan" {
		t.Fatalf("after refresh: %+v", got)
	}
	m.Sources.ASNURL = srv.URL + "/broken.tsv.gz"
	if err := m.RefreshASN(t.Context()); err == nil {
		t.Fatal("a broken file was taken")
	}
	if got := m.DB.Lookup(netip.MustParseAddr("5.160.10.1")); got.ASN != 44244 {
		t.Fatalf("a broken refresh replaced the table: %+v", got)
	}
	again := &Manager{DB: &DB{}, Dir: m.Dir, Sources: m.Sources}
	again.LoadLocal()
	if asn, city := again.DB.Loaded(); !asn || !city {
		t.Fatalf("a restart did not load the files kept: asn %v city %v", asn, city)
	}
}

func TestRangeToPrefixes(t *testing.T) {
	for _, c := range []struct {
		start, end string
		want       []string
	}{
		{"5.160.0.0", "5.160.255.255", []string{"5.160.0.0/16"}},
		{"5.160.0.0", "5.160.4.191", []string{"5.160.0.0/22", "5.160.4.0/25", "5.160.4.128/26"}},
		{"10.0.0.1", "10.0.0.1", []string{"10.0.0.1/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"2a01:4f8::", "2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff", []string{"2a01:4f8::/32"}},
	} {
		var got []string
		for _, p := range RangeToPrefixes(netip.MustParseAddr(c.start), netip.MustParseAddr(c.end)) {
			got = append(got, p.String())
		}
		if strings.Join(got, " ") != strings.Join(c.want, " ") {
			t.Errorf("%s–%s: %v, want %v", c.start, c.end, got, c.want)
		}
	}
}
