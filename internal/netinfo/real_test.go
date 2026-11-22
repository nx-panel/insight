package netinfo

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestRealFiles parses the publishers' real files when a directory holding
// them (ip2asn.tsv.gz, city.csv.gz) is named in NX_INSIGHT_REAL_NETINFO,
// and reports the time and memory the kept tables take. Not run by default:
// the files are ~100 MB and change every month.
func TestRealFiles(t *testing.T) {
	dir := os.Getenv("NX_INSIGHT_REAL_NETINFO")
	if dir == "" {
		t.Skip("NX_INSIGHT_REAL_NETINFO names no directory")
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	f, err := os.Open(filepath.Join(dir, "ip2asn.tsv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	asn, err := ReadASN(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	asnTook := time.Since(start)
	start = time.Now()
	f, err = os.Open(filepath.Join(dir, "city.csv.gz"))
	if err != nil {
		t.Fatal(err)
	}
	city, err := ReadCity(f, []string{"IR", "RU", "CN"})
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	cityTook := time.Since(start)
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	db := &DB{}
	db.SetASN(asn)
	db.SetCity(city)
	t.Logf("asn: %d ranges in %s; city (IR,RU,CN): %d ranges in %s; heap +%d MB",
		len(asn.spans), asnTook, len(city.spans), cityTook, (after.HeapAlloc-before.HeapAlloc)>>20)
	for _, a := range []string{"5.160.10.1", "2.176.1.1", "95.165.1.1", "36.110.1.1", "88.198.10.20", "2a01:4f8::1"} {
		t.Logf("%s: %+v", a, db.Lookup(netip.MustParseAddr(a)))
	}
	if db.Lookup(netip.MustParseAddr("5.160.10.1")).Country != "IR" {
		t.Fatal("an Iranian address is not in Iran")
	}
	start = time.Now()
	got, err := ScanCity(filepath.Join(dir, "city.csv.gz"), []netip.Addr{netip.MustParseAddr("88.198.10.20"), netip.MustParseAddr("2a01:4f8::1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("node scan in %s: %+v", time.Since(start), got)
}
