package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

const (
	// Window is what one pass reads.
	Window = 24 * time.Hour
	// MaxRows bounds the paths sent: the busiest, so a pass costs a few
	// thousand tokens however large the fleet.
	MaxRows = 120
	// minAccepted drops paths too quiet to say anything.
	minAccepted = 5
)

// Path is one row of the table a pass sends.
type Path struct {
	ASN      uint32
	Org      string
	Node     uint
	Inbound  string
	Network  string
	Accepted uint64
	// Ratios in percent; Normal* from the path's recent normal, -1 when it
	// has none yet.
	Success, NormalFail, Early, NormalEarly int
	Fail                                    int
	Replayed                                uint64
	RTTMs                                   uint64
	Degraded                                bool
}

// HostNode is a node as the model sees it: its id and where it is hosted,
// never its address or name.
type HostNode struct {
	ID      uint
	Country string
	Org     string
}

// Table is everything one pass sends for one client country.
type Table struct {
	Country string
	At      time.Time
	Nodes   []HostNode
	Paths   []Path
	Outages []uint32
	Probed  []detect.Suspicion
	Alerts  map[string]int
}

// State is what the detector knows now.
type State interface {
	Degraded() map[detect.Key]bool
	Outages() map[uint32]bool
}

// Build reads the last Window of country's paths.
func Build(ctx context.Context, gdb *gorm.DB, st State, org func(uint32) string, country string, now time.Time) (Table, error) {
	t := Table{Country: country, At: now, Alerts: map[string]int{}}
	since := now.Add(-Window).Truncate(time.Hour).Unix()
	type row struct {
		ClientASN                                    uint32
		NodeID                                       uint
		Inbound, Network                             string
		Accepted, Authed, EarlyClose, Failed, Replay uint64
		RTTSum                                       uint64 `gorm:"column:rtt_sum"`
		RTTN                                         uint64 `gorm:"column:rtt_n"`
	}
	var rows []row
	tx := gdb.WithContext(ctx)
	if err := tx.Model(&model.PathHour{}).
		Select("client_asn, node_id, inbound, network, SUM(accepted) AS accepted, SUM(authed) AS authed, "+
			"SUM(early_close) AS early_close, SUM(failed_tls + failed_auth + failed_timeout + failed_reset + failed_eof + failed_other) AS failed, "+
			"SUM(replayed) AS replay, SUM(rtt_sum) AS rtt_sum, SUM(rtt_n) AS rtt_n").
		// No ASN 0 (detect.OtherASN): it is whatever had no network of its
		// own that hour, and a finding about "it" would be about nothing —
		// and 0 in a finding means "every network". The traffic floor is
		// applied before the cut to MaxRows, not after it.
		Where("hour >= ? AND country = ? AND client_asn <> ?", since, country, detect.OtherASN).
		Group("client_asn, node_id, inbound, network").Having("SUM(accepted) >= ?", minAccepted).
		Order("accepted DESC").Limit(MaxRows).
		Scan(&rows).Error; err != nil {
		return t, err
	}
	var baselines []detect.Baseline
	if err := tx.Where("slot = ?", detect.RecentSlot).Find(&baselines).Error; err != nil {
		return t, err
	}
	normals := map[detect.Key]detect.Baseline{}
	for _, b := range baselines {
		normals[detect.Key{Node: b.NodeID, Inbound: b.Inbound, ASN: b.ASN, Network: b.Network}] = b
	}
	degraded := map[detect.Key]bool{}
	if st != nil {
		degraded = st.Degraded()
	}
	nodes, asns := map[uint]bool{}, map[uint32]bool{}
	for _, r := range rows {
		if r.Accepted < minAccepted {
			continue
		}
		k := detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}
		p := Path{
			ASN: r.ClientASN, Node: r.NodeID, Inbound: r.Inbound, Network: r.Network, Accepted: r.Accepted,
			Success: pct(r.Authed, r.Accepted), Fail: pct(r.Failed, r.Accepted), Early: pct(r.EarlyClose, max(r.Authed, 1)),
			NormalFail: -1, NormalEarly: -1, Replayed: r.Replay, Degraded: degraded[k],
		}
		if org != nil {
			p.Org = org(r.ClientASN)
		}
		if r.RTTN > 0 {
			p.RTTMs = r.RTTSum / r.RTTN
		}
		if b, ok := normals[k]; ok && b.N > 0 {
			p.NormalFail, p.NormalEarly = int(b.MeanFail*100+0.5), int(b.MeanEarly*100+0.5)
		}
		t.Paths = append(t.Paths, p)
		nodes[r.NodeID], asns[r.ClientASN] = true, true
	}
	if len(t.Paths) == 0 {
		return t, nil
	}
	var infos []model.NodeNetinfo
	if err := tx.Find(&infos).Error; err != nil {
		return t, err
	}
	for _, n := range infos {
		if !nodes[n.NodeID] {
			continue
		}
		_, o, c, _ := n.Effective()
		t.Nodes = append(t.Nodes, HostNode{ID: n.NodeID, Country: c, Org: o})
	}
	if st != nil {
		for a := range st.Outages() {
			if asns[a] {
				t.Outages = append(t.Outages, a)
			}
		}
		sort.Slice(t.Outages, func(i, j int) bool { return t.Outages[i] < t.Outages[j] })
	}
	if err := tx.Where("score > 0").Order("score DESC").Limit(20).Find(&t.Probed).Error; err != nil {
		return t, err
	}
	probed := t.Probed[:0]
	for _, s := range t.Probed {
		if nodes[s.NodeID] {
			probed = append(probed, s)
		}
	}
	t.Probed = probed
	var alerts []detect.Alert
	if err := tx.Where("at >= ?", now.Add(-Window).Unix()).Find(&alerts).Error; err != nil {
		return t, err
	}
	for _, a := range alerts {
		if asns[a.ASN] || (a.Kind == detect.KindProbed && nodes[a.NodeID]) {
			t.Alerts[a.Kind]++
		}
	}
	return t, nil
}

func pct(part, whole uint64) int {
	if whole == 0 {
		return 0
	}
	return int((part*100 + whole/2) / whole)
}

// Text is the table as the model reads it: pipe-separated, a header per
// section, a few kilobytes at most.
func (t Table) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "client_country=%s window=24h now=%s\n", t.Country, t.At.UTC().Format(time.RFC3339))
	b.WriteString("\n# nodes: node|host_country|host_org\n")
	for _, n := range t.Nodes {
		fmt.Fprintf(&b, "%d|%s|%s\n", n.ID, n.Country, clean(n.Org))
	}
	b.WriteString("\n# paths: asn|org|node|inbound|net|accepted|success%|fail%|normal_fail%|early_close%|normal_early%|replayed|rtt_ms|state\n")
	for _, p := range t.Paths {
		state := "ok"
		if p.Degraded {
			state = "degraded"
		}
		fmt.Fprintf(&b, "%d|%s|%d|%s|%s|%d|%d|%d|%s|%d|%s|%d|%d|%s\n",
			p.ASN, clean(p.Org), p.Node, clean(p.Inbound), p.Network, p.Accepted, p.Success, p.Fail,
			normal(p.NormalFail), p.Early, normal(p.NormalEarly), p.Replayed, p.RTTMs, state)
	}
	b.WriteString("\n# asn_outages_now: asn\n")
	for _, a := range t.Outages {
		fmt.Fprintf(&b, "%d\n", a)
	}
	b.WriteString("\n# probed_endpoints: node|inbound|score|replayed_6h|follow_up_fail_6h\n")
	for _, s := range t.Probed {
		fmt.Fprintf(&b, "%d|%s|%d|%d|%d\n", s.NodeID, clean(s.Inbound), s.Score, s.Replayed, s.FollowUpFail)
	}
	b.WriteString("\n# alerts_24h: kind|count\n")
	kinds := make([]string, 0, len(t.Alerts))
	for k := range t.Alerts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		fmt.Fprintf(&b, "%s|%d\n", k, t.Alerts[k])
	}
	return b.String()
}

func normal(v int) string {
	if v < 0 {
		return "-"
	}
	return fmt.Sprint(v)
}

// clean cuts a name down before it goes into the table. The names are
// other people's text — a network's registered name, an inbound's tag, the
// provider the admin typed for a node — and the table is a prompt: only
// letters, digits, spaces, '-' and '_' pass, forty runes of them. That
// keeps a name from breaking a line or a column and from carrying a URL or
// a dotted address as written; it does not make it meaningless — a tag
// that spells a host name or an address in letters and digits still says
// it, and forty runes are room for a short sentence. What a wrong answer
// can do is bounded elsewhere: every finding is checked against the
// numbers (supported).
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_':
		case r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '|' || r == '/' || r == ',':
			r = ' '
		default:
			continue
		}
		if n++; n > 40 {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}
