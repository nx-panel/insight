// Package hints computes the subscription ordering document and hands it to
// the panel (PUT /api/v1/subscriptions/order-hints, telemetry:write):
// for each client ASN Insight has
// enough data on, its nodes in order of how well they work for that ASN,
// and within a node its inbounds the same way. Links are only moved, never
// hidden — the panel enforces that.
//
// The CIDRs a group names are the ASN's announced ranges from the network
// information (public routing data). During an asn.outage the ASN's group is
// left as it was: ranking paths that are all down by their last
// minutes says nothing about which will come back first.
package hints

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

const (
	// Window is how far back a path's record is read.
	Window = 6 * time.Hour
	// Lifetime is how long a pushed document holds; it is pushed again well
	// before.
	Lifetime = 6 * time.Hour
	// RefreshEvery re-pushes an unchanged document, extending it.
	RefreshEvery = time.Hour
	// minAccepted is the traffic below which a path is not ranked.
	minAccepted = 10
	// margin is how much better a node or inbound must score than the one
	// ahead of it before the pushed order changes: ratios from a few dozen
	// connections wobble by a few points every flush, and each reorder is a
	// PUT and a reshuffled subscription for the whole network.
	margin   = 0.1
	maxCIDRs = 200000
)

// Document is the panel's order-hints body.
type Document struct {
	V         int     `json:"v"`
	ExpiresAt int64   `json:"expires_at"`
	Groups    []Group `json:"groups"`
}

// Group is one client ASN's order.
type Group struct {
	ASN   uint32   `json:"-"`
	CIDRs []string `json:"cidrs"`
	Order Order    `json:"order"`
}

// Order is nodes by id, and per node id its inbounds by tag.
type Order struct {
	Nodes    []uint              `json:"nodes"`
	Inbounds map[string][]string `json:"inbounds,omitempty"`
}

// Putter is the panel client's one call this package makes.
type Putter interface {
	Put(ctx context.Context, path string, body any, out any) error
}

// State is what the detector says now.
type State interface {
	Outages() map[uint32]bool
	Degraded() map[detect.Key]bool
}

// Hints computes and pushes.
type Hints struct {
	DB       *gorm.DB
	Prefixes func(asns map[uint32]bool) map[uint32][]netip.Prefix
	Panel    func() Putter
	State    State
	Now      func() time.Time

	mu       sync.Mutex
	last     map[uint32]Group // what was pushed, per ASN
	hash     string
	pushedAt time.Time
}

func (h *Hints) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

type row struct {
	ClientASN  uint32
	NodeID     uint
	Inbound    string
	Network    string
	Accepted   uint64
	Authed     uint64
	EarlyClose uint64
}

type scored struct {
	tag   string
	score float64
}

// Compute builds the document from the last Window of cells.
func (h *Hints) Compute(ctx context.Context) (Document, error) {
	now := h.now()
	var rows []row
	err := h.DB.WithContext(ctx).Model(&model.PathHour{}).
		Select("client_asn, node_id, inbound, network, SUM(accepted) AS accepted, SUM(authed) AS authed, SUM(early_close) AS early_close").
		Where("hour >= ? AND client_asn <> 0", now.Add(-Window).Truncate(time.Hour).Unix()).
		Group("client_asn, node_id, inbound, network").Scan(&rows).Error
	if err != nil {
		return Document{}, err
	}
	degraded, outages := map[detect.Key]bool{}, map[uint32]bool{}
	if h.State != nil {
		degraded, outages = h.State.Degraded(), h.State.Outages()
	}
	// Per ASN, per node, its inbounds' scores; a node is as good as its best
	// inbound, since the client tries the next link of the same node next.
	perASN := map[uint32]map[uint][]scored{}
	for _, r := range rows {
		if r.Accepted < minAccepted {
			continue
		}
		s := float64(r.Authed) / float64(r.Accepted)
		if r.Authed > 0 {
			s *= 1 - float64(r.EarlyClose)/float64(r.Authed)
		}
		if degraded[detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}] {
			s = -1
		}
		if perASN[r.ClientASN] == nil {
			perASN[r.ClientASN] = map[uint][]scored{}
		}
		perASN[r.ClientASN][r.NodeID] = mergeTag(perASN[r.ClientASN][r.NodeID], scored{r.Inbound, s})
	}
	// A degraded path ranks last whether or not it still has traffic in the
	// window: one that has been dead for the whole of it has no row to be
	// ranked by, and dropping it would drop its node, and with one node left
	// the network's whole group — the panel's default order back exactly
	// when the order matters.
	for k := range degraded {
		if k.ASN == detect.OtherASN {
			continue
		}
		if perASN[k.ASN] == nil {
			perASN[k.ASN] = map[uint][]scored{}
		}
		perASN[k.ASN][k.Node] = mergeTag(perASN[k.ASN][k.Node], scored{k.Inbound, -1})
	}
	h.mu.Lock()
	last := h.last
	h.mu.Unlock()
	want := map[uint32]bool{}
	groups := map[uint32]Group{}
	for asn, nodes := range perASN {
		if outages[asn] {
			continue
		}
		if len(nodes) < 2 {
			continue // one node: nothing to order
		}
		groups[asn] = order(asn, nodes, last[asn])
		want[asn] = true
	}
	// An ASN in an outage keeps the group it had, however long the outage
	// and whatever traffic is left; one with no group pushed before (or
	// since Insight started) gets none now either.
	for asn := range outages {
		if g, ok := last[asn]; ok {
			groups[asn] = g
			want[asn] = true
		}
	}
	prefixes := map[uint32][]netip.Prefix{}
	if h.Prefixes != nil {
		prefixes = h.Prefixes(want)
	}
	asns := make([]uint32, 0, len(groups))
	for asn := range groups {
		asns = append(asns, asn)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	doc := Document{V: 1, ExpiresAt: now.Add(Lifetime).Unix(), Groups: []Group{}}
	total := 0
	for _, asn := range asns {
		g := groups[asn]
		if len(g.CIDRs) == 0 {
			// Nothing narrower than a client prefix: the panel keeps no
			// narrower one (it must never hold one client's address), and a
			// few announced ranges are. Widened here, once each.
			seen := map[netip.Prefix]bool{}
			for _, p := range prefixes[asn] {
				if widest := clientPrefixBits(p.Addr()); p.Bits() > widest {
					p = netip.PrefixFrom(p.Addr(), widest).Masked()
				}
				if !seen[p] {
					seen[p] = true
					g.CIDRs = append(g.CIDRs, p.String())
				}
			}
		}
		if len(g.CIDRs) == 0 || total+len(g.CIDRs) > maxCIDRs {
			continue
		}
		total += len(g.CIDRs)
		doc.Groups = append(doc.Groups, g)
	}
	return doc, nil
}

func mergeTag(list []scored, s scored) []scored {
	for i := range list {
		if list[i].tag == s.tag {
			// Two networks of one inbound: the worse one decides, so a
			// broken UDP side is not hidden by a working TCP one.
			if s.score < list[i].score {
				list[i].score = s.score
			}
			return list
		}
	}
	return append(list, s)
}

func order(asn uint32, nodes map[uint][]scored, prev Group) Group {
	g := Group{ASN: asn, Order: Order{Inbounds: map[string][]string{}}}
	best := map[uint]float64{}
	ids := make([]uint, 0, len(nodes))
	for id, ins := range nodes {
		key := strconv.FormatUint(uint64(id), 10)
		scores := map[string]float64{}
		tags := make([]string, 0, len(ins))
		for _, in := range ins {
			scores[in.tag] = in.score
			tags = append(tags, in.tag)
		}
		tags = settle(prev.Order.Inbounds[key], tags, scores, func(a, b string) bool { return a < b })
		g.Order.Inbounds[key] = tags
		best[id] = scores[tags[0]]
		for _, sc := range scores {
			best[id] = max(best[id], sc)
		}
		ids = append(ids, id)
	}
	g.Order.Nodes = settle(prev.Order.Nodes, ids, best, func(a, b uint) bool { return a < b })
	return g
}

// settle orders items by score, best first — unless prev holds the same
// items in an order no pair of which is wrong by more than margin, which is
// then kept.
func settle[T comparable](prev, items []T, score map[T]float64, less func(a, b T) bool) []T {
	if len(prev) == len(items) {
		same := true
		for i, p := range prev {
			if _, ok := score[p]; !ok {
				same = false
				break
			}
			// Against every item ahead of it, not only its neighbour: steps
			// of less than the margin each can add up to an order that is
			// plainly upside down.
			for _, ahead := range prev[:i] {
				if score[p] > score[ahead]+margin {
					same = false
				}
			}
			if !same {
				break
			}
		}
		if same {
			return append([]T(nil), prev...)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if score[items[i]] != score[items[j]] {
			return score[items[i]] > score[items[j]]
		}
		return less(items[i], items[j])
	})
	return items
}

// Push computes the document and PUTs it when it changed, or when the one
// pushed is due to be extended. Nothing to order pushes nothing: the last
// document expires by itself.
func (h *Hints) Push(ctx context.Context) error {
	if h.Panel == nil {
		return nil
	}
	client := h.Panel()
	if client == nil {
		return nil
	}
	doc, err := h.Compute(ctx)
	if err != nil {
		return err
	}
	if len(doc.Groups) == 0 {
		return nil
	}
	raw, _ := json.Marshal(doc.Groups)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	h.mu.Lock()
	fresh := hash == h.hash && h.now().Sub(h.pushedAt) < RefreshEvery
	h.mu.Unlock()
	if fresh {
		return nil
	}
	if err := client.Put(ctx, "/subscriptions/order-hints", doc, nil); err != nil {
		return err
	}
	last := map[uint32]Group{}
	for _, g := range doc.Groups {
		last[g.ASN] = g
	}
	h.mu.Lock()
	h.hash, h.pushedAt, h.last = hash, h.now(), last
	h.mu.Unlock()
	log.Printf("hints: pushed %d groups", len(doc.Groups))
	return nil
}

// clientPrefixBits is the panel's rule for a client prefix, which the panel
// applies again whatever is sent: /24, /48, and /40 for a 6to4 address,
// whose /48 is one IPv4 client.
func clientPrefixBits(addr netip.Addr) int {
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		return 24
	case addr.As16()[0] == 0x20 && addr.As16()[1] == 0x02:
		return 40
	default:
		return 48
	}
}
