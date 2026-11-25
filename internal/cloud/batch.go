package cloud

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

// Batch is one closed hour as Mode B sends it: the global key, Insight's
// own verdict, the counters. Nothing names a node, an inbound, an
// address, a domain or the panel.
type Batch struct {
	V       int    `json:"v"`
	Hour    int64  `json:"hour"`
	Insight string `json:"insight"`
	Cells   []Cell `json:"cells"`
}

// Cell is one cell of a batch.
type Cell struct {
	ASN       uint32 `json:"asn"`
	CC        string `json:"cc"`
	Region    string `json:"region"`
	Org       string `json:"org"`
	NodeASN   uint32 `json:"node_asn"`
	NodeCC    string `json:"node_cc"`
	NodeOrg   string `json:"node_org"`
	Proto     string `json:"proto"`
	Transport string `json:"transport"`
	Security  string `json:"security"`
	Front     string `json:"front"`
	Network   string `json:"network"`
	Verdict   string `json:"verdict"`

	Accepted     uint64            `json:"accepted"`
	Authed       uint64            `json:"authed"`
	EarlyClose   uint64            `json:"early_close"`
	Failed       map[string]uint64 `json:"failed,omitempty"`
	Sigs         map[string]uint64 `json:"sigs,omitempty"`
	Replayed     uint64            `json:"replayed"`
	FollowUpFail uint64            `json:"follow_up_fail"`
	RTTSum       uint64            `json:"rtt_sum"`
	RTTN         uint64            `json:"rtt_n"`
	DurSum       uint64            `json:"dur_sum"`
	DurN         uint64            `json:"dur_n"`
}

// The verdicts, the cloud's list.
const (
	VerdictOK         = "ok"
	VerdictDegraded   = "degraded"
	VerdictOutage     = "asn_outage"
	VerdictTunnelDown = "tunnel_down"
	VerdictNodeDown   = "node_blocked"
)

// MaxCells bounds a batch: the cloud stores at most this many, the busiest.
const MaxCells = 800

// Sources are what Mode B reads: the database, the shapes and the names
// for build, the tunnels for Mark.
type Sources struct {
	DB      *gorm.DB
	Shapes  func() map[uint]map[string]ingest.Shape
	Tunnels func() []tunnels.View
	Org     func(uint32) string
	Version string
	// Ready, when set, says whether the ingest has polled and flushed once,
	// so the shapes hold what the panel names; nil is always ready.
	Ready func() bool
}

type globalKey struct {
	asn                                                 uint32
	cc, region                                          string
	nodeASN                                             uint32
	nodeCC                                              string
	proto, transport, security, front, network, verdict string
}

// build makes the batch of the hour starting at hour, with the number of
// rows the hour holds, so a caller can tell an empty hour from one whose
// rows no shape named. A cell whose inbound the panel's shapes do not name
// (an older panel, a deleted inbound), or whose client has no network or
// country, is left out: it has no strategy or no network to be about. Its
// verdict is the strongest any evaluation in the hour found (Mark,
// marks.go, nodesBlocked): its relay's tunnel down, its network in an
// outage, its node's address blocked, its path degraded, in that order.
func build(ctx context.Context, src Sources, hour int64) (Batch, int, error) {
	b := Batch{V: 1, Hour: hour, Insight: src.Version, Cells: []Cell{}}
	var rows []model.PathHour
	tx := src.DB.WithContext(ctx)
	if err := tx.Where("hour = ? AND client_asn <> ?", hour, model.OtherASN).Find(&rows).Error; err != nil {
		return b, 0, err
	}
	if len(rows) == 0 {
		return b, 0, nil
	}
	rowCount := len(rows)
	var sigRows []model.PathSigHour
	if err := tx.Where("hour = ? AND client_asn <> ?", hour, model.OtherASN).Find(&sigRows).Error; err != nil {
		return b, rowCount, err
	}
	sigs := map[model.PathCell]map[string]uint64{}
	for _, s := range sigRows {
		m := sigs[s.PathCell]
		if m == nil {
			m = map[string]uint64{}
			sigs[s.PathCell] = m
		}
		m[s.Sig] += s.N
	}
	var nets []model.NodeNetinfo
	if err := tx.Find(&nets).Error; err != nil {
		return b, rowCount, err
	}
	hosts := map[uint]model.NodeNetinfo{}
	for _, n := range nets {
		hosts[n.NodeID] = n
	}
	var shapes map[uint]map[string]ingest.Shape
	if src.Shapes != nil {
		shapes = src.Shapes()
	}
	marks, err := marksOf(tx, hour)
	if err != nil {
		return b, rowCount, err
	}

	cells := map[globalKey]*Cell{}
	for _, r := range rows {
		sh, ok := shapes[r.NodeID][r.Inbound]
		if !ok || r.Country == "" {
			continue
		}
		verdict := VerdictOK
		switch {
		case marks.cut[r.NodeID]:
			verdict = VerdictTunnelDown
		case marks.outages[r.ClientASN]:
			verdict = VerdictOutage
		case marks.blocked[r.NodeID]:
			verdict = VerdictNodeDown
		case marks.degraded[detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}]:
			verdict = VerdictDegraded
		}
		host := hosts[r.NodeID]
		nodeASN, nodeOrg, nodeCC, _ := host.Effective()
		// Keyed on the region as sent: two that differ only past the clip
		// are one cell, or the cloud would refuse the hour for a cell twice.
		k := globalKey{
			asn: r.ClientASN, cc: r.Country, region: clip(r.Region, 96), nodeASN: nodeASN, nodeCC: nodeCC,
			proto: token(sh.Type), transport: token(sh.Transport), security: security(sh.Security), front: front(sh.Fronted),
			network: r.Network, verdict: verdict,
		}
		if k.proto == "" || (k.network != "tcp" && k.network != "udp") {
			continue
		}
		c := cells[k]
		if c == nil {
			org := ""
			if src.Org != nil {
				org = src.Org(r.ClientASN)
			}
			c = &Cell{
				ASN: k.asn, CC: k.cc, Region: k.region, Org: clip(org, 128), NodeASN: k.nodeASN, NodeCC: k.nodeCC, NodeOrg: clip(nodeOrg, 128),
				Proto: k.proto, Transport: k.transport, Security: k.security, Front: k.front, Network: k.network, Verdict: k.verdict,
			}
			cells[k] = c
		}
		add(c, r.PathCounters, sigs[r.PathCell])
	}
	for _, c := range cells {
		b.Cells = append(b.Cells, *c)
	}
	// A cell's weight is its connections: accepted, or authed for a cell
	// with none accepted (an endpoint cell, WireGuard, has only handshakes).
	weight := func(c Cell) uint64 {
		if c.Accepted > 0 {
			return c.Accepted
		}
		return c.Authed
	}
	sort.Slice(b.Cells, func(i, j int) bool {
		wi, wj := weight(b.Cells[i]), weight(b.Cells[j])
		if wi != wj {
			return wi > wj
		}
		return less(b.Cells[i], b.Cells[j])
	})
	if len(b.Cells) > MaxCells {
		b.Cells = b.Cells[:MaxCells]
	}
	return b, rowCount, nil
}

func add(c *Cell, p model.PathCounters, sigs map[string]uint64) {
	c.Accepted += p.Accepted
	c.Authed += p.Authed
	c.EarlyClose += p.EarlyClose
	c.Replayed += p.Replayed
	c.FollowUpFail += p.FollowUpFail
	c.RTTSum += p.RTTSum
	c.RTTN += p.RTTN
	c.DurSum += p.DurSum
	c.DurN += p.DurN
	for class, n := range map[string]uint64{
		"tls": p.FailedTLS, "auth": p.FailedAuth, "timeout": p.FailedTimeout, "reset": p.FailedReset, "eof": p.FailedEOF,
		"other": p.FailedOther, "ingress_noroute": p.FailedNoRoute, "quic_initial_bad": p.FailedQUIC,
	} {
		if n == 0 {
			continue
		}
		if c.Failed == nil {
			c.Failed = map[string]uint64{}
		}
		c.Failed[class] += n
	}
	for sig, n := range sigs {
		if c.Sigs == nil {
			c.Sigs = map[string]uint64{}
		}
		c.Sigs[sig] += n
	}
}

// nodesBlocked reads a node's address as blocked at one evaluation when,
// outside any ASN outage, at least four in five of the paths judged on it
// are degraded, across two client networks or more and two inbounds or
// more: a strategy block shows on one inbound, an address block on all of
// them at once. A path counts whether its window holds traffic or not,
// since a dead address leaves none.
func nodesBlocked(judged, degraded map[detect.Key]bool, outages map[uint32]bool) map[uint]bool {
	type tally struct {
		paths, bad int
		asns       map[uint32]bool
		inbounds   map[string]bool
	}
	per := map[uint]*tally{}
	for k := range judged {
		if outages[k.ASN] {
			continue
		}
		t := per[k.Node]
		if t == nil {
			t = &tally{asns: map[uint32]bool{}, inbounds: map[string]bool{}}
			per[k.Node] = t
		}
		t.paths++
		if degraded[k] {
			t.bad++
			t.asns[k.ASN] = true
			t.inbounds[k.Inbound] = true
		}
	}
	out := map[uint]bool{}
	for id, t := range per {
		if t.paths > 0 && t.bad*5 >= t.paths*4 && len(t.asns) >= 2 && len(t.inbounds) >= 2 {
			out[id] = true
		}
	}
	return out
}

// token is a protocol or transport name as the cloud takes it: lower case,
// letters, digits, '.', '_' and '-', at most 32.
func token(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(out) < 32; i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || ((c == '.' || c == '_' || c == '-') && len(out) > 0) {
			out = append(out, c)
		}
	}
	return string(out)
}

func security(s string) string {
	switch s {
	case "tls", "reality", "none":
		return s
	}
	return ""
}

func front(fronted bool) string {
	if fronted {
		return "cdn"
	}
	return "direct"
}

// less orders two cells of equal weight by their key, field by field.
func less(a, b Cell) bool {
	return cmp.Or(
		cmp.Compare(a.ASN, b.ASN), strings.Compare(a.CC, b.CC), strings.Compare(a.Region, b.Region),
		cmp.Compare(a.NodeASN, b.NodeASN), strings.Compare(a.NodeCC, b.NodeCC),
		strings.Compare(a.Proto, b.Proto), strings.Compare(a.Transport, b.Transport), strings.Compare(a.Security, b.Security),
		strings.Compare(a.Front, b.Front), strings.Compare(a.Network, b.Network), strings.Compare(a.Verdict, b.Verdict),
	) < 0
}

// clip cuts s to n UTF-16 units, as the cloud measures a string (a
// character outside the basic plane counts two), never inside a pair.
func clip(s string, n int) string {
	units := 0
	for i, r := range s {
		w := 1
		if r > 0xFFFF {
			w = 2
		}
		if units+w > n {
			return s[:i]
		}
		units += w
	}
	return s
}

// decode reads a gzipped batch back.
func decode(gz []byte) (*Batch, error) {
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	var b Batch
	if err := json.NewDecoder(io.LimitReader(r, 8<<20)).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}
