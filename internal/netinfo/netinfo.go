// Package netinfo answers what network an address is on: its autonomous
// system (iptoasn.com's ranges) and, for clients in the countries the
// install keeps regions for, its province and city (DB-IP City Lite) —
// nx-panel docs/path-telemetry.md P5. Each install downloads both itself
// (P17 a) and keeps them in its data directory; nothing is sent anywhere.
//
// Attribution: DB-IP's data is CC BY 4.0 and must be credited where its
// results are shown (Attribution); iptoasn.com states no licence on its
// page (checked 2026-11-22) and is redistributed by others as public domain
// (PDDL); it is credited too.
package netinfo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// Attribution is the credit the admin web and the docs show.
const Attribution = "IP address to ASN data from iptoasn.com. IP geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0."

// Info is what an address is on. ASN 0 is unknown (not routed, or no
// data); Region and City are empty outside the kept countries.
type Info struct {
	ASN     uint32
	Org     string
	Country string
	Region  string
	City    string
}

// DB is the loaded tables, swapped whole on a refresh.
type DB struct {
	asn  atomic.Pointer[asnTable]
	city atomic.Pointer[geoTable]
}

// Lookup is addr's network. Safe for concurrent use with a refresh.
func (d *DB) Lookup(addr netip.Addr) Info {
	addr = addr.Unmap()
	var info Info
	if t := d.asn.Load(); t != nil {
		info.ASN, info.Country = t.find(addr)
		info.Org = t.orgs[info.ASN]
	}
	if t := d.city.Load(); t != nil {
		if g, ok := t.find(addr); ok {
			info.Region, info.City = g.region, g.city
			if info.Country == "" {
				info.Country = g.country
			}
		}
	}
	return info
}

// Loaded reports which tables are in.
func (d *DB) Loaded() (asn, city bool) {
	return d.asn.Load() != nil, d.city.Load() != nil
}

// SetASN and SetCity install tables read elsewhere (a test, a refresh).
func (d *DB) SetASN(t *asnTable)  { d.asn.Store(t) }
func (d *DB) SetCity(t *geoTable) { d.city.Store(t) }

// ranges keyed by the address as 16 bytes, so one sorted slice per family
// serves a binary search.
type span struct {
	start, end [16]byte
}

func (s span) contains(a [16]byte) bool {
	return bytes.Compare(s.start[:], a[:]) <= 0 && bytes.Compare(a[:], s.end[:]) <= 0
}

// asnTable is iptoasn's ranges.
type asnTable struct {
	spans []span
	asns  []uint32
	ccs   []string
	orgs  map[uint32]string
}

func (t *asnTable) find(addr netip.Addr) (uint32, string) {
	i, ok := search(t.spans, addr.As16())
	if !ok {
		return 0, ""
	}
	return t.asns[i], t.ccs[i]
}

// search is the span holding a, if any: the last one starting at or before
// it, when it also ends at or after it.
func search(spans []span, a [16]byte) (int, bool) {
	i := sort.Search(len(spans), func(i int) bool { return bytes.Compare(spans[i].start[:], a[:]) > 0 }) - 1
	if i < 0 || !spans[i].contains(a) {
		return 0, false
	}
	return i, true
}

// ReadASN parses iptoasn's TSV (range_start, range_end, AS_number,
// country_code, AS_description), gzipped or not. AS 0 rows (not routed)
// are left out.
func ReadASN(r io.Reader) (*asnTable, error) {
	r, err := maybeGunzip(r)
	if err != nil {
		return nil, err
	}
	t := &asnTable{orgs: map[uint32]string{}}
	type row struct {
		s   span
		asn uint32
		cc  string
	}
	var rows []row
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 5 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		asn, err3 := strconv.ParseUint(f[2], 10, 32)
		if err1 != nil || err2 != nil || err3 != nil || start.Is4() != end.Is4() {
			return nil, fmt.Errorf("asn line %d: %q", line, sc.Text())
		}
		if asn == 0 {
			continue
		}
		cc := strings.ToUpper(f[3])
		if cc == "NONE" {
			cc = ""
		}
		rows = append(rows, row{span{start.As16(), end.As16()}, uint32(asn), cc})
		if _, ok := t.orgs[uint32(asn)]; !ok {
			t.orgs[uint32(asn)] = f[4]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("asn: no ranges")
	}
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i].s.start[:], rows[j].s.start[:]) < 0 })
	for _, r := range rows {
		t.spans = append(t.spans, r.s)
		t.asns = append(t.asns, r.asn)
		t.ccs = append(t.ccs, r.cc)
	}
	return t, nil
}

// geo is one city range's answer.
type geo struct {
	country, region, city string
}

// geoTable is DB-IP's ranges for the kept countries.
type geoTable struct {
	spans []span
	geos  []geo
}

func (t *geoTable) find(addr netip.Addr) (geo, bool) {
	i, ok := search(t.spans, addr.As16())
	if !ok {
		return geo{}, false
	}
	return t.geos[i], true
}

// cityRow is one line of DB-IP City Lite: ip_start, ip_end, continent,
// country, stateprov, city, latitude, longitude.
type cityRow struct {
	s span
	g geo
}

func readCityRows(r io.Reader, keep func(cityRow) bool) error {
	r, err := maybeGunzip(r)
	if err != nil {
		return err
	}
	cr := csv.NewReader(bufio.NewReaderSize(r, 256<<10))
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	line := 0
	for {
		f, err := cr.Read()
		if err == io.EOF {
			return nil
		}
		line++
		if err != nil {
			return fmt.Errorf("city line %d: %w", line, err)
		}
		if len(f) < 6 {
			continue
		}
		start, err1 := netip.ParseAddr(f[0])
		end, err2 := netip.ParseAddr(f[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("city line %d: %q", line, strings.Join(f, ","))
		}
		row := cityRow{s: span{start.As16(), end.As16()}, g: geo{country: strings.ToUpper(f[3]), region: f[4], city: f[5]}}
		if !keep(row) {
			return nil
		}
	}
}

// ReadCity parses DB-IP City Lite (CSV, gzipped or not), keeping the
// ranges of the given countries only: the whole file is millions of rows,
// and a region is only ever asked for a client in one of them.
func ReadCity(r io.Reader, countries []string) (*geoTable, error) {
	t := &geoTable{}
	intern := map[string]string{}
	in := func(s string) string {
		if v, ok := intern[s]; ok {
			return v
		}
		intern[s] = s
		return s
	}
	err := readCityRows(r, func(row cityRow) bool {
		if slices.Contains(countries, row.g.country) {
			t.spans = append(t.spans, row.s)
			t.geos = append(t.geos, geo{in(row.g.country), in(row.g.region), in(row.g.city)})
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	idx := make([]int, len(t.spans))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return bytes.Compare(t.spans[idx[a]].start[:], t.spans[idx[b]].start[:]) < 0 })
	sorted := &geoTable{spans: make([]span, len(idx)), geos: make([]geo, len(idx))}
	for i, j := range idx {
		sorted.spans[i], sorted.geos[i] = t.spans[j], t.geos[j]
	}
	return sorted, nil
}

// ScanCity reads the city file once for a handful of addresses in any
// country — the nodes, which are abroad, where the kept table has nothing.
func ScanCity(path string, addrs []netip.Addr) (map[netip.Addr]Info, error) {
	out := map[netip.Addr]Info{}
	if len(addrs) == 0 {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	want := make(map[netip.Addr][16]byte, len(addrs))
	for _, a := range addrs {
		want[a.Unmap()] = a.Unmap().As16()
	}
	err = readCityRows(f, func(row cityRow) bool {
		for a, b := range want {
			if row.s.contains(b) {
				out[a] = Info{Country: row.g.country, Region: row.g.region, City: row.g.city}
				delete(want, a)
			}
		}
		return len(want) > 0
	})
	return out, err
}

func maybeGunzip(r io.Reader) (io.Reader, error) {
	br := bufio.NewReader(r)
	magic, err := br.Peek(2)
	if err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(br)
	}
	return br, nil
}
