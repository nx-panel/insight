// Package metrics serves Insight's numbers to Prometheus: GET /metrics behind a bearer token,
// in the text exposition format written by hand, as the panel's is — no
// client library for a few dozen lines.
//
// The client network is the dimension the panel's /metrics cannot have: per
// node, inbound and client ASN, the detector's last fifteen minutes. It is
// bounded — per node and inbound the busiest MaxASNs networks have series of
// their own and the rest are one asn="other" — and it carries an AS number
// and its registered name, never a prefix or an address of a client.
package metrics

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

const (
	// MaxASNs is how many client networks per node and inbound get series
	// of their own.
	MaxASNs = 10
	// maxPaths bounds the path series in all, maxDegraded the degraded
	// paths listed, maxProbed the probe scores.
	maxPaths    = 5000
	maxDegraded = 500
	maxProbed   = 200
	// Other is the label of the networks past MaxASNs.
	Other = "other"
)

// Sources are what the numbers are read from; any may be nil.
type Sources struct {
	DB      *gorm.DB
	Detect  *detect.Detector
	Ingest  *ingest.Ingest
	Tunnels *tunnels.Watcher
	// Org names an AS number.
	Org func(uint32) string
	Now func() time.Time
}

// Handler is GET /metrics, its token read on every request since the
// settings page may change it. An empty token turns the route off: it answers
// 404, as a route that is not there.
func Handler(tokenOf func() string, src Sources) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := tokenOf()
		want := []byte("Bearer " + token)
		if token == "" {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="insight metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		if err := Write(r.Context(), w, src); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// pathKey is one path series' labels, after folding.
type pathKey struct {
	node    uint
	inbound string
	asn     string // the AS number, or Other
	network string
}

// Write writes every metric.
func Write(ctx context.Context, out io.Writer, src Sources) error {
	now := time.Now()
	if src.Now != nil {
		now = src.Now()
	}
	names := map[uint]string{}
	if src.DB != nil {
		var nodes []model.NodeNetinfo
		if err := src.DB.WithContext(ctx).Select("node_id", "name").Find(&nodes).Error; err != nil {
			return err
		}
		for _, n := range nodes {
			names[n.NodeID] = n.Name
		}
	}
	org := func(asn string) string {
		if asn == Other || src.Org == nil {
			return ""
		}
		n, _ := strconv.ParseUint(asn, 10, 32)
		return src.Org(uint32(n))
	}
	nodeName := func(id uint) string {
		if n := names[id]; n != "" {
			return n
		}
		return "#" + strconv.FormatUint(uint64(id), 10)
	}
	m := &writer{w: out}

	// The feed.
	if src.Ingest != nil {
		st := src.Ingest.Status()
		m.help("insight_feed_up", "gauge", "1 while Insight reads the panel's path telemetry.")
		m.sample("insight_feed_up", nil, boolean(st.State == ingest.StateOK))
		counting := 0
		for _, n := range st.Nodes {
			if n.State == ingest.StateNodeOn {
				counting++
			}
		}
		m.help("insight_nodes_counting", "gauge", "Nodes the panel lists as counting.")
		m.sample("insight_nodes_counting", nil, float64(counting))
		m.help("insight_feed_gaps_total", "counter", "Times the panel dropped samples before Insight read them, since Insight started.")
		m.sample("insight_feed_gaps_total", nil, float64(st.Gaps))
	}

	if src.Detect != nil {
		// The last fifteen minutes per path, the busiest networks first.
		recent := src.Detect.Recent()
		type group struct {
			node    uint
			inbound string
		}
		byGroup := map[group][]detect.Key{}
		for k := range recent {
			g := group{k.Node, k.Inbound}
			byGroup[g] = append(byGroup[g], k)
		}
		weight := func(k detect.Key) uint64 { c := recent[k]; return c.Accepted + c.Authed }
		folded := map[pathKey]model.PathCounters{}
		for g, keys := range byGroup {
			// By network first, so the busiest of an ASN's tcp and udp
			// decides its place, then by weight.
			perASN := map[uint32]uint64{}
			for _, k := range keys {
				perASN[k.ASN] += weight(k)
			}
			asns := make([]uint32, 0, len(perASN))
			for a := range perASN {
				asns = append(asns, a)
			}
			sort.Slice(asns, func(i, j int) bool {
				if perASN[asns[i]] != perASN[asns[j]] {
					return perASN[asns[i]] > perASN[asns[j]]
				}
				return asns[i] < asns[j]
			})
			own := map[uint32]bool{}
			for i, a := range asns {
				if i < MaxASNs {
					own[a] = true
				}
			}
			for _, k := range keys {
				asn := Other
				if own[k.ASN] {
					asn = strconv.FormatUint(uint64(k.ASN), 10)
				}
				pk := pathKey{g.node, g.inbound, asn, k.Network}
				c := folded[pk]
				r := recent[k]
				c.Accepted += r.Accepted
				c.Authed += r.Authed
				c.FailedAuth += r.FailedAuth
				c.EarlyClose += r.EarlyClose
				folded[pk] = c
			}
		}
		keys := make([]pathKey, 0, len(folded))
		for k := range folded {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessPath(keys[i], keys[j]) })
		if len(keys) > maxPaths {
			keys = keys[:maxPaths]
		}
		var shapes map[uint]map[string]ingest.Shape
		if src.Ingest != nil {
			shapes = src.Ingest.Shapes()
		}
		labels := func(k pathKey) []string {
			kind := "inbound"
			// "endpoint" only for a handshake-only (WireGuard) path, whose
			// success ratio is unknown; OpenVPN and OpenConnect count like
			// an inbound and are labelled one.
			if shapes[k.node][k.inbound].HandshakeOnly() {
				kind = ingest.KindEndpoint
			}
			return []string{
				"node", nodeName(k.node), "node_id", strconv.FormatUint(uint64(k.node), 10),
				"inbound", k.inbound, "kind", kind, "asn", k.asn, "org", org(k.asn), "network", k.network,
			}
		}
		labelled := make([][]string, len(keys))
		for i, k := range keys {
			labelled[i] = labels(k)
		}
		for _, metric := range []struct {
			name, help string
			value      func(model.PathCounters) uint64
		}{
			{"insight_path_accepted_15m", "Connections accepted in the last fifteen minutes, per node, inbound and client network (a WireGuard endpoint, kind=endpoint, accepts none it can be seen to).", func(c model.PathCounters) uint64 { return c.Accepted }},
			{"insight_path_authed_15m", "Sessions authenticated in the last fifteen minutes (a WireGuard endpoint's, kind=endpoint: handshakes that worked).", func(c model.PathCounters) uint64 { return c.Authed }},
			{"insight_path_failed_15m", "Connections that failed before authenticating in the last fifteen minutes.", func(c model.PathCounters) uint64 { return c.FailedAuth }},
			{"insight_path_early_close_15m", "Authenticated sessions cut within seconds having moved almost nothing, in the last fifteen minutes.", func(c model.PathCounters) uint64 { return c.EarlyClose }},
		} {
			m.help(metric.name, "gauge", metric.help)
			for i, k := range keys {
				m.sample(metric.name, labelled[i], float64(metric.value(folded[k])))
			}
		}

		// The detector's judgement.
		degraded := src.Detect.Degraded()
		dk := make([]detect.Key, 0, len(degraded))
		for k := range degraded {
			if k.ASN != detect.OtherASN {
				dk = append(dk, k)
			}
		}
		sort.Slice(dk, func(i, j int) bool {
			return lessPath(pathKey{dk[i].Node, dk[i].Inbound, strconv.FormatUint(uint64(dk[i].ASN), 10), dk[i].Network},
				pathKey{dk[j].Node, dk[j].Inbound, strconv.FormatUint(uint64(dk[j].ASN), 10), dk[j].Network})
		})
		if len(dk) > maxDegraded {
			dk = dk[:maxDegraded]
		}
		m.help("insight_paths_degraded", "gauge", "Paths the detector marks degraded now.")
		m.sample("insight_paths_degraded", nil, float64(len(degraded)))
		m.help("insight_path_degraded", "gauge", "1 for each path degraded now (at most 500 listed).")
		for _, k := range dk {
			asn := strconv.FormatUint(uint64(k.ASN), 10)
			m.sample("insight_path_degraded", []string{
				"node", nodeName(k.Node), "node_id", strconv.FormatUint(uint64(k.Node), 10),
				"inbound", k.Inbound, "asn", asn, "org", org(asn), "network", k.Network,
			}, 1)
		}
		outages := src.Detect.Outages()
		oa := make([]uint32, 0, len(outages))
		for a := range outages {
			oa = append(oa, a)
		}
		sort.Slice(oa, func(i, j int) bool { return oa[i] < oa[j] })
		m.help("insight_asn_outage", "gauge", "1 for each client network cut off now (every path to it down on two or more nodes).")
		for _, a := range oa {
			asn := strconv.FormatUint(uint64(a), 10)
			m.sample("insight_asn_outage", []string{"asn", asn, "org", org(asn)}, 1)
		}
	}

	if src.Tunnels != nil {
		m.help("insight_tunnel_down", "gauge", "1 for a tunnel with no link now, 0 for one linked; a tunnel switched off or not judged yet is not listed.")
		for _, t := range src.Tunnels.Views() {
			if !t.Enabled || t.State == tunnels.Unknown {
				continue
			}
			m.sample("insight_tunnel_down", []string{"tunnel", t.Name, "relay", nodeName(t.RelayID), "relay_id", strconv.FormatUint(uint64(t.RelayID), 10)},
				boolean(t.State == tunnels.Down))
		}
	}

	if src.DB != nil {
		var probed []detect.Suspicion
		if err := src.DB.WithContext(ctx).Where("score > 0").Order("score DESC, node_id, inbound").Limit(maxProbed).Find(&probed).Error; err != nil {
			return err
		}
		m.help("insight_probe_score", "gauge", "Each endpoint's probing score, 0–100, over the last six hours (at most 200, the highest).")
		for _, s := range probed {
			m.sample("insight_probe_score", []string{"node", nodeName(s.NodeID), "node_id", strconv.FormatUint(uint64(s.NodeID), 10), "inbound", s.Inbound}, float64(s.Score))
		}
		var counts []struct {
			Kind string
			N    int64
		}
		if err := src.DB.WithContext(ctx).Model(&detect.Alert{}).Select("kind, COUNT(*) AS n").Where("at >= ?", now.Add(-24*time.Hour).Unix()).
			Group("kind").Order("kind").Scan(&counts).Error; err != nil {
			return err
		}
		m.help("insight_alerts_24h", "gauge", "Alerts raised in the last 24 hours, by kind.")
		for _, c := range counts {
			m.sample("insight_alerts_24h", []string{"kind", c.Kind}, float64(c.N))
		}
	}
	return m.err
}

func lessPath(a, b pathKey) bool {
	if a.node != b.node {
		return a.node < b.node
	}
	if a.inbound != b.inbound {
		return a.inbound < b.inbound
	}
	if a.asn != b.asn {
		return a.asn < b.asn
	}
	return a.network < b.network
}

func boolean(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// writer is the text exposition format, enough of it.
type writer struct {
	w   io.Writer
	err error
}

func (m *writer) help(name, kind, text string) {
	m.printf("# HELP %s %s\n# TYPE %s %s\n", name, escapeHelp(text), name, kind)
}

// sample writes one line; labels are name, value pairs.
func (m *writer) sample(name string, labels []string, v float64) {
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(escapeLabel(labels[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	b.WriteByte('\n')
	m.printf("%s", b.String())
}

func (m *writer) printf(format string, args ...any) {
	if m.err == nil {
		_, m.err = fmt.Fprintf(m.w, format, args...)
	}
}

var (
	labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(s string) string { return labelEscaper.Replace(s) }
func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
