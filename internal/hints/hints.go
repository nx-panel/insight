// Package hints computes the subscription ordering document and hands it to
// the panel (PUT /api/v1/subscriptions/order-hints, telemetry:write;
// nx-panel docs/path-telemetry.md §4.3, P6): for each client ASN Insight has
// enough data on, its nodes in order of how well they work for that ASN,
// and within a node its inbounds the same way. Links are only moved, never
// hidden — the panel enforces that.
//
// The CIDRs a group names are the ASN's announced ranges from the network
// information (public routing data). During an asn.outage the ASN's group is
// left as it was (P20 a): ranking paths that are all down by their last
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

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"gorm.io/gorm"
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
	maxCIDRs    = 200000
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
	h.mu.Lock()
	last := h.last
	h.mu.Unlock()
	want := map[uint32]bool{}
	groups := map[uint32]Group{}
	for asn, nodes := range perASN {
		if outages[asn] {
			if g, ok := last[asn]; ok {
				groups[asn] = g // left as it was
			}
			continue
		}
		if len(nodes) < 2 {
			continue // one node: nothing to order
		}
		groups[asn] = order(asn, nodes)
		want[asn] = true
	}
	// An ASN in an outage with no group pushed before gets none now either.
	for asn := range outages {
		if _, ok := groups[asn]; ok {
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
			for _, p := range prefixes[asn] {
				g.CIDRs = append(g.CIDRs, p.String())
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

func order(asn uint32, nodes map[uint][]scored) Group {
	type nodeScore struct {
		id    uint
		score float64
	}
	var ns []nodeScore
	g := Group{ASN: asn, Order: Order{Inbounds: map[string][]string{}}}
	for id, ins := range nodes {
		sort.SliceStable(ins, func(i, j int) bool {
			if ins[i].score != ins[j].score {
				return ins[i].score > ins[j].score
			}
			return ins[i].tag < ins[j].tag
		})
		tags := make([]string, len(ins))
		for i, in := range ins {
			tags[i] = in.tag
		}
		g.Order.Inbounds[strconv.FormatUint(uint64(id), 10)] = tags
		ns = append(ns, nodeScore{id, ins[0].score})
	}
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].score != ns[j].score {
			return ns[i].score > ns[j].score
		}
		return ns[i].id < ns[j].id
	})
	for _, n := range ns {
		g.Order.Nodes = append(g.Order.Nodes, n.id)
	}
	return g
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
