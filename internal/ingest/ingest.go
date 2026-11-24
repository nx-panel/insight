// Package ingest pulls the panel's path telemetry (GET
// /api/v1/telemetry/paths), turns each sample's client prefix into its ASN
// and region and forgets the prefix, and adds the counters into hourly cells
// in Insight's database (nx-panel docs/path-telemetry.md §4.4, §4.6).
//
// Polled samples accumulate in memory and are written every FlushEvery, one
// transaction a flush, with the poll cursor in the same transaction: a
// restart loses nothing the panel still holds (about fifteen minutes), and a
// longer outage is reported as a gap.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
)

const (
	// PollEvery is how often the panel is asked; its buffer keeps about
	// fifteen minutes, so a minute leaves room for a slow restart.
	PollEvery = time.Minute
	// FlushEvery is how often the accumulated cells are written.
	FlushEvery = 5 * time.Minute
	// TopK is how many client ASNs get their own cell per node and inbound
	// in an hour; the rest fold into ASN 0 (§4.6).
	TopK = 30
	// pageLimit is the samples asked for per request.
	pageLimit = 20000
	// A sample older than the panel can have held it plus slack, or from
	// the future, carries a wrong clock.
	maxSampleAge   = 6 * 3600
	maxSampleAhead = 3600
	// OtherASN is the folded cell's ASN.
	OtherASN = model.OtherASN
)

// Poll states, for the admin web.
const (
	StateWaiting     = "waiting"     // not registered with a panel yet
	StateOK          = "ok"          // polling
	StateUnsupported = "unsupported" // the panel predates path telemetry
	StateNoScope     = "no-scope"    // the token lacks telemetry:read
	StateError       = "error"       // the last poll failed otherwise
)

const stateCursor = "poll_cursor"

// Getter is the panel client's one call this package makes.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// Sample is one panel sample as polled.
type Sample struct {
	Cursor     uint64            `json:"cursor"`
	NodeID     uint              `json:"node_id"`
	DateTime   int64             `json:"date_time"`
	Inbound    string            `json:"inbound"`
	Network    string            `json:"network"`
	Prefix     string            `json:"prefix"`
	SourceKind string            `json:"source_kind"`
	Accepted   uint32            `json:"accepted"`
	Failed     map[string]uint32 `json:"failed"`
	// FailedSig counts the failures by signature,
	// "<class>/<bytes>/<seconds>" (nx-panel docs/path-telemetry.md PT12).
	FailedSig    map[string]uint32 `json:"failed_sig"`
	Authed       uint32            `json:"authed"`
	EarlyClose   uint32            `json:"early_close"`
	Replayed     uint32            `json:"replayed"`
	FollowUpFail uint32            `json:"follow_up_fail"`
	DurP50       uint32            `json:"dur_p50"`
	RTTP50       uint32            `json:"rtt_p50"`
	RetransPPM   uint32            `json:"retrans_ppm"`
	Up           int64             `json:"up"`
	Down         int64             `json:"down"`
}

// NodeState is one node's telemetry state as the panel reports it, with
// the shape of what it serves (nx-panel docs/path-telemetry.md P22): an
// older panel sends no inbounds.
type NodeState struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Inbounds []Shape `json:"inbounds,omitempty"`
}

// Shape is one inbound or listening endpoint a node serves, by the tag its
// cells carry.
type Shape struct {
	Tag       string `json:"tag"`
	Kind      string `json:"kind"` // inbound | endpoint
	Type      string `json:"type"`
	Transport string `json:"transport,omitempty"`
	Security  string `json:"security,omitempty"`
	Fronted   bool   `json:"fronted"`
}

// KindEndpoint is a Shape of a WireGuard, OpenVPN or OpenConnect endpoint.
// A WireGuard server answers a handshake it cannot authenticate with
// silence, so its cells count only what got through — handshakes and
// bytes — never accepted or failed (P27).
const KindEndpoint = "endpoint"

// TunnelSample is one node's counts for one node-to-node tunnel link since
// its previous drain (P26), as polled.
type TunnelSample struct {
	Cursor      uint64            `json:"cursor"`
	NodeID      uint              `json:"node_id"`
	DateTime    int64             `json:"date_time"`
	Tunnel      string            `json:"tunnel"`
	Peer        string            `json:"peer"`
	Server      string            `json:"server"`
	Side        string            `json:"side"`
	Attempts    uint32            `json:"attempts"`
	Up          uint32            `json:"up"`
	Failed      map[string]uint32 `json:"failed"`
	Flapped     uint32            `json:"flapped"`
	LifetimeP50 uint32            `json:"lifetime_p50"`
}

// A node's state as the panel lists it: StateNodeOn is the one that counts
// (the panel's gateway.PathNodeOn). StateSkewed is Insight's own: a node
// whose clock is wrong enough that its samples are dropped.
const (
	StateNodeOn = "on"
	StateSkewed = "skewed"
)

// Counting is the set of nodes a poll listed as counting, for the detector:
// a node listed in any other state, or not listed at all — deleted — is not
// in it. nil when the poll carried no list (an old panel), which is "not
// known", never "none".
func Counting(nodes []NodeState) map[uint]bool {
	if nodes == nil {
		return nil
	}
	counting := map[uint]bool{}
	for _, n := range nodes {
		if n.State == StateNodeOn {
			counting[n.ID] = true
		}
	}
	return counting
}

type page struct {
	Active  bool           `json:"active"`
	Cursor  uint64         `json:"cursor"`
	Gap     bool           `json:"gap"`
	Samples []Sample       `json:"samples"`
	Tunnels []TunnelSample `json:"tunnels"`
	Nodes   []NodeState    `json:"nodes"`
}

// Status is what the admin web shows about the feed.
type Status struct {
	State    string      `json:"state"`
	Error    string      `json:"error,omitempty"`
	LastPoll time.Time   `json:"lastPoll"`
	Gaps     int         `json:"gaps"`
	LastGap  time.Time   `json:"lastGap"`
	Nodes    []NodeState `json:"nodes"`
	Pending  int         `json:"pending"`
	// Skewed counts the samples dropped for a timestamp far from now.
	Skewed int `json:"skewed"`
}

type cellKey struct {
	hour int64
	model.PathCell
}

type groupKey struct {
	hour    int64
	node    uint
	inbound string
}

// Ingest is the poll, the accumulation and the flush.
type Ingest struct {
	DB  *gorm.DB
	Net *netinfo.DB
	// Panel is the client to poll, nil while unregistered.
	Panel func() Getter
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Observe, when set, sees each sample's counters as polled, by node,
	// inbound, client ASN (before top-K folding) and network — the
	// detector's window.
	Observe func(node uint, inbound string, asn uint32, network string, c model.PathCounters)
	// AfterFlush runs after each successful flush in Run: the detection and
	// the hints work on what is now in the database.
	AfterFlush func(ctx context.Context)
	// Fed is told after every poll whether it worked — false for one that
	// failed or was not made — and which nodes the panel listed. Gapped is
	// told when the panel says it dropped samples before they were read.
	Fed    func(ok bool, nodes []NodeState)
	Gapped func()

	mu      sync.Mutex
	pending map[cellKey]*model.PathCounters
	// tunnels are the tunnel links' counts waiting for the flush.
	tunnels map[model.TunnelCell]*model.TunnelCounters
	// known is, per hour and node and inbound, the ASNs that have their own
	// cell already — in the database or pending — so top-K folding holds
	// across flushes.
	known  map[groupKey]map[uint32]bool
	cursor uint64
	loaded bool
	status Status
}

func (in *Ingest) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// Status is a copy of the feed's status.
func (in *Ingest) Status() Status {
	in.mu.Lock()
	defer in.mu.Unlock()
	s := in.status
	if s.State == "" {
		s.State = StateWaiting
	}
	s.Nodes = append([]NodeState(nil), s.Nodes...)
	s.Pending = len(in.pending)
	return s
}

// Shapes is what each node served as of the last poll, by node and tag;
// empty before one, or from a panel that does not list it.
func (in *Ingest) Shapes() map[uint]map[string]Shape {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make(map[uint]map[string]Shape, len(in.status.Nodes))
	for _, n := range in.status.Nodes {
		if len(n.Inbounds) == 0 {
			continue
		}
		m := make(map[string]Shape, len(n.Inbounds))
		for _, sh := range n.Inbounds {
			m[sh.Tag] = sh
		}
		out[n.ID] = m
	}
	return out
}

// Run polls and flushes for the life of ctx, and flushes once more on the
// way out.
func (in *Ingest) Run(ctx context.Context) {
	poll := time.NewTicker(PollEvery)
	flush := time.NewTicker(FlushEvery)
	defer poll.Stop()
	defer flush.Stop()
	in.pollLogged(ctx)
	for {
		select {
		case <-ctx.Done():
			if err := in.Flush(context.Background()); err != nil {
				log.Printf("ingest: flush on the way out: %v", err)
			}
			return
		case <-poll.C:
			in.pollLogged(ctx)
		case <-flush.C:
			if err := in.Flush(ctx); err != nil {
				log.Printf("ingest: flush: %v", err)
			} else if in.AfterFlush != nil {
				in.AfterFlush(ctx)
			}
		}
	}
}

func (in *Ingest) pollLogged(ctx context.Context) {
	if err := in.Poll(ctx); err != nil {
		log.Printf("ingest: poll: %v", err)
	}
}

// fed tells whoever watches the feed (the detector) how the poll went.
func (in *Ingest) fed(ok bool, nodes []NodeState) {
	if in.Fed != nil {
		in.Fed(ok, nodes)
	}
}

// Poll asks the panel for everything after the cursor, a page at a time.
func (in *Ingest) Poll(ctx context.Context) error {
	if in.Panel == nil {
		in.fed(false, nil)
		return nil
	}
	client := in.Panel()
	if client == nil {
		in.fed(false, nil)
		return nil
	}
	// Not before the network tables are in: a sample looked up against
	// nothing would be stored for good as "no network, no country". The
	// panel keeps fifteen minutes for a reader that is late.
	if in.Net != nil {
		if asn, _ := in.Net.Loaded(); !asn {
			in.mu.Lock()
			in.status.Error = "waiting for the network database"
			in.mu.Unlock()
			in.fed(false, nil)
			return nil
		}
	}
	if err := in.loadCursor(); err != nil {
		in.fed(false, nil)
		return err
	}
	for range 50 { // a backlog of a million samples at most per poll
		in.mu.Lock()
		since := in.cursor
		in.mu.Unlock()
		var p page
		err := client.Get(ctx, "/telemetry/paths?since="+strconv.FormatUint(since, 10)+"&limit="+strconv.Itoa(pageLimit), &p)
		if err != nil {
			in.setError(err)
			in.fed(false, nil)
			return err
		}
		if p.Gap && in.Gapped != nil {
			in.Gapped() // samples were dropped before they were read
		}
		skewed := in.take(p)
		// A node whose samples were dropped for their timestamp is not
		// being counted, whatever the panel says of it: without this its
		// paths would read as silent, and silence as a block.
		nodes := p.Nodes
		if len(skewed) > 0 && nodes != nil {
			// A copy, never nil for a list that came empty: nil is "the
			// poll carried no list" (Counting).
			nodes = append(make([]NodeState, 0, len(p.Nodes)), p.Nodes...)
			for i := range nodes {
				if skewed[nodes[i].ID] {
					nodes[i].State = StateSkewed
				}
			}
		}
		in.fed(true, nodes)
		in.mu.Lock()
		stuck := in.cursor == since
		in.mu.Unlock()
		// The panel's limit counts the cells and the tunnel links together.
		if len(p.Samples)+len(p.Tunnels) < pageLimit || stuck {
			return nil
		}
	}
	return nil
}

func (in *Ingest) setError(err error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.status.LastPoll = in.now()
	in.status.Error = err.Error()
	switch {
	case panel.IsStatus(err, http.StatusNotFound):
		in.status.State = StateUnsupported
	case panel.IsStatus(err, http.StatusForbidden):
		in.status.State = StateNoScope
	default:
		in.status.State = StateError
	}
}

// take adds one page into the pending cells. A sample's prefix is read
// here, looked up and dropped: it is never stored and never leaves this
// function.
func (in *Ingest) take(p page) (skewed map[uint]bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	now := in.now()
	in.status.State, in.status.Error, in.status.LastPoll = StateOK, "", now
	in.status.Nodes = p.Nodes
	if p.Gap {
		in.status.Gaps++
		in.status.LastGap = now
	}
	if in.pending == nil {
		in.pending = map[cellKey]*model.PathCounters{}
	}
	for _, s := range p.Samples {
		// A sample stamped far from now is a node whose clock is wrong: its
		// hour would be compacted and deleted within the day, silently.
		if d := now.Unix() - s.DateTime; d > maxSampleAge || d < -maxSampleAhead {
			in.status.Skewed++
			if skewed == nil {
				skewed = map[uint]bool{}
			}
			skewed[s.NodeID] = true
			continue
		}
		var info netinfo.Info
		if pfx, err := netip.ParsePrefix(s.Prefix); err == nil && in.Net != nil {
			info = in.Net.Lookup(pfx.Addr())
		}
		k := cellKey{hour: s.DateTime - s.DateTime%3600, PathCell: model.PathCell{
			NodeID: s.NodeID, Inbound: s.Inbound, ClientASN: info.ASN, Country: info.Country,
			Region: info.Region, Network: s.Network, SourceKind: s.SourceKind,
		}}
		c := in.pending[k]
		if c == nil {
			c = &model.PathCounters{}
			in.pending[k] = c
		}
		add(c, s)
		if in.Observe != nil {
			var one model.PathCounters
			add(&one, s)
			in.Observe(s.NodeID, s.Inbound, info.ASN, s.Network, one)
		}
	}
	for _, ts := range p.Tunnels {
		if d := now.Unix() - ts.DateTime; d > maxSampleAge || d < -maxSampleAhead {
			in.status.Skewed++
			continue
		}
		k := model.TunnelCell{
			Hour: ts.DateTime - ts.DateTime%3600, NodeID: ts.NodeID,
			Tunnel: ts.Tunnel, Peer: ts.Peer, Server: ts.Server, Side: ts.Side,
		}
		if in.tunnels == nil {
			in.tunnels = map[model.TunnelCell]*model.TunnelCounters{}
		}
		c := in.tunnels[k]
		if c == nil {
			c = &model.TunnelCounters{}
			in.tunnels[k] = c
		}
		addTunnel(c, ts)
	}
	// The panel's cursor, also when it is behind ours: a panel that
	// restarted (or another panel, or a restored database) numbers from
	// somewhere else and answers a cursor it never gave with everything it
	// holds and gap set. Keeping the larger one would ask for, and add, all
	// of that again on every poll.
	if p.Gap || p.Cursor > in.cursor {
		in.cursor = p.Cursor
	}
	return skewed
}

// addTunnel adds one tunnel sample into its hour's counters.
func addTunnel(c *model.TunnelCounters, s TunnelSample) {
	c.Attempts += uint64(s.Attempts)
	c.Up += uint64(s.Up)
	c.Flapped += uint64(s.Flapped)
	for class, n := range s.Failed {
		switch class {
		case "dial":
			c.FailedDial += uint64(n)
		case "tls":
			c.FailedTLS += uint64(n)
		case "preface":
			c.FailedPreface += uint64(n)
		case "refused":
			c.FailedRefused += uint64(n)
		case "timeout":
			c.FailedTimeout += uint64(n)
		case "reset":
			c.FailedReset += uint64(n)
		case "eof":
			c.FailedEOF += uint64(n)
		default:
			c.FailedOther += uint64(n)
		}
	}
	if s.LifetimeP50 > 0 {
		c.LifetimeSum += uint64(s.LifetimeP50)
		c.LifetimeN++
	}
}

func add(c *model.PathCounters, s Sample) {
	c.Accepted += uint64(s.Accepted)
	c.Authed += uint64(s.Authed)
	c.EarlyClose += uint64(s.EarlyClose)
	c.Replayed += uint64(s.Replayed)
	c.FollowUpFail += uint64(s.FollowUpFail)
	for class, n := range s.Failed {
		switch class {
		case "tls":
			c.FailedTLS += uint64(n)
		case "auth":
			c.FailedAuth += uint64(n)
		case "timeout":
			c.FailedTimeout += uint64(n)
		case "reset":
			c.FailedReset += uint64(n)
		case "eof":
			c.FailedEOF += uint64(n)
		case "ingress_noroute":
			c.FailedNoRoute += uint64(n)
		case "quic_initial_bad":
			c.FailedQUIC += uint64(n)
		default:
			c.FailedOther += uint64(n)
		}
	}
	w := uint64(max(s.Authed, 1))
	if s.DurP50 > 0 {
		c.DurSum += uint64(s.DurP50) * w
		c.DurN += w
	}
	if s.RTTP50 > 0 {
		c.RTTSum += uint64(s.RTTP50) * w
		c.RTTN += w
	}
	if s.RetransPPM > 0 || s.RTTP50 > 0 {
		c.RetransSum += uint64(s.RetransPPM) * w
		c.RetransN += w
	}
	c.Up += s.Up
	c.Down += s.Down
	for sig, n := range s.FailedSig {
		if n == 0 || !model.ValidSig(sig) {
			continue
		}
		if c.Sigs == nil {
			c.Sigs = map[string]uint64{}
		}
		c.Sigs[sig] += uint64(n)
	}
}

func (in *Ingest) loadCursor() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.loaded {
		return nil
	}
	var st model.State
	err := in.DB.Where("key = ?", stateCursor).First(&st).Error
	switch {
	case err == nil:
		n, perr := strconv.ParseUint(st.Value, 10, 64)
		if perr != nil {
			return fmt.Errorf("the stored cursor %q: %w", st.Value, perr)
		}
		in.cursor = n
	case errors.Is(err, gorm.ErrRecordNotFound):
	default:
		return err
	}
	in.loaded = true
	return nil
}

// Flush writes the pending cells and the cursor in one transaction.
func (in *Ingest) Flush(ctx context.Context) error {
	in.mu.Lock()
	pending, tunnels, cursor := in.pending, in.tunnels, in.cursor
	in.pending, in.tunnels = nil, nil
	in.mu.Unlock()
	if len(pending) == 0 && len(tunnels) == 0 && !in.loadedCursor() {
		return nil
	}
	err := in.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		folded, err := in.fold(tx, pending)
		if err != nil {
			return err
		}
		for k, c := range folded {
			row := model.PathHour{Hour: k.hour, PathCell: k.PathCell, PathCounters: *c}
			if err := UpsertAdd(tx, &row, "hour"); err != nil {
				return err
			}
			if err := upsertSigs(tx, k.hour, k.PathCell, c.Sigs); err != nil {
				return err
			}
		}
		for k, c := range tunnels {
			if err := upsertTunnel(tx, &model.TunnelHour{TunnelCell: k, TunnelCounters: *c}); err != nil {
				return err
			}
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "key"}},
			DoUpdates: clause.AssignmentColumns([]string{"value"}),
		}).Create(&model.State{Key: stateCursor, Value: strconv.FormatUint(cursor, 10)}).Error
	})
	if err != nil {
		// Put the cells back: the next flush tries them again, merged with
		// what came meanwhile.
		in.mu.Lock()
		// What fold admitted was not written: read it again next time.
		in.known = nil
		if in.pending == nil {
			in.pending = map[cellKey]*model.PathCounters{}
		}
		for k, c := range pending {
			if have := in.pending[k]; have != nil {
				addCounters(have, c)
			} else {
				in.pending[k] = c
			}
		}
		if in.tunnels == nil && len(tunnels) > 0 {
			in.tunnels = map[model.TunnelCell]*model.TunnelCounters{}
		}
		for k, c := range tunnels {
			if have := in.tunnels[k]; have != nil {
				addTunnelCounters(have, c)
			} else {
				in.tunnels[k] = c
			}
		}
		in.mu.Unlock()
		return err
	}
	return nil
}

func (in *Ingest) loadedCursor() bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.loaded
}

// fold applies top-K: per hour, node and inbound, an ASN gets a cell of its
// own while fewer than TopK have one; past that its counters go to the
// OtherASN cell, which carries no country or region so it stays one cell.
// New ASNs are admitted busiest first.
func (in *Ingest) fold(tx *gorm.DB, pending map[cellKey]*model.PathCounters) (map[cellKey]*model.PathCounters, error) {
	in.mu.Lock()
	if in.known == nil {
		in.known = map[groupKey]map[uint32]bool{}
	}
	in.mu.Unlock()
	keys := make([]cellKey, 0, len(pending))
	for k := range pending {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return weight(pending[keys[i]]) > weight(pending[keys[j]]) })
	out := make(map[cellKey]*model.PathCounters, len(pending))
	for _, k := range keys {
		known, err := in.knownFor(tx, groupKey{k.hour, k.NodeID, k.Inbound})
		if err != nil {
			return nil, err
		}
		dest := k
		if k.ClientASN != OtherASN && !known[k.ClientASN] {
			if countReal(known) < TopK {
				known[k.ClientASN] = true
			} else {
				dest.ClientASN, dest.Country, dest.Region = OtherASN, "", ""
			}
		}
		if have := out[dest]; have != nil {
			addCounters(have, pending[k])
		} else {
			c := *pending[k]
			// The signatures are a map: a copy of the struct would share it,
			// and a failed flush puts pending back, so adding the next cell
			// into this one must not reach pending's.
			c.Sigs = maps.Clone(c.Sigs)
			out[dest] = &c
		}
	}
	return out, nil
}

func countReal(known map[uint32]bool) int {
	n := 0
	for asn := range known {
		if asn != OtherASN {
			n++
		}
	}
	return n
}

func weight(c *model.PathCounters) uint64 { return c.Accepted + c.Authed + c.FailedAuth + c.FailedTLS }

// knownFor loads, once per group, the ASNs the database already holds a
// cell for.
func (in *Ingest) knownFor(tx *gorm.DB, g groupKey) (map[uint32]bool, error) {
	in.mu.Lock()
	known := in.known[g]
	in.mu.Unlock()
	if known != nil {
		return known, nil
	}
	var asns []uint32
	if err := tx.Model(&model.PathHour{}).Where("hour = ? AND node_id = ? AND inbound = ?", g.hour, g.node, g.inbound).
		Distinct().Pluck("client_asn", &asns).Error; err != nil {
		return nil, err
	}
	known = map[uint32]bool{}
	for _, a := range asns {
		known[a] = true
	}
	in.mu.Lock()
	in.known[g] = known
	// Forget the groups of hours long gone, so the map stays small.
	cut := g.hour - 3*3600
	for k := range in.known {
		if k.hour < cut {
			delete(in.known, k)
		}
	}
	in.mu.Unlock()
	return known, nil
}

func addCounters(a, b *model.PathCounters) {
	a.Accepted += b.Accepted
	a.Authed += b.Authed
	a.EarlyClose += b.EarlyClose
	a.FailedTLS += b.FailedTLS
	a.FailedAuth += b.FailedAuth
	a.FailedTimeout += b.FailedTimeout
	a.FailedReset += b.FailedReset
	a.FailedEOF += b.FailedEOF
	a.FailedOther += b.FailedOther
	a.FailedNoRoute += b.FailedNoRoute
	a.FailedQUIC += b.FailedQUIC
	a.Replayed += b.Replayed
	a.FollowUpFail += b.FollowUpFail
	a.DurSum += b.DurSum
	a.DurN += b.DurN
	a.RTTSum += b.RTTSum
	a.RTTN += b.RTTN
	a.RetransSum += b.RetransSum
	a.RetransN += b.RetransN
	a.Up += b.Up
	a.Down += b.Down
	for sig, n := range b.Sigs {
		if a.Sigs == nil {
			a.Sigs = map[string]uint64{}
		}
		a.Sigs[sig] += n
	}
}

// upsertSigs adds a cell's failure signatures into path_sig_hours.
func upsertSigs(tx *gorm.DB, hour int64, cell model.PathCell, sigs map[string]uint64) error {
	if len(sigs) == 0 {
		return nil
	}
	keys := make([]string, 0, len(sigs))
	for k := range sigs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	cols := []clause.Column{{Name: "hour"}}
	for _, c := range []string{"node_id", "inbound", "client_asn", "country", "region", "network", "source_kind", "sig"} {
		cols = append(cols, clause.Column{Name: c})
	}
	for _, k := range keys {
		row := model.PathSigHour{Hour: hour, PathCell: cell, Sig: k, N: sigs[k]}
		if err := tx.Clauses(clause.OnConflict{Columns: cols, DoUpdates: clause.Assignments(map[string]any{
			"n": gorm.Expr("path_sig_hours.n + excluded.n"),
		})}).Create(&row).Error; err != nil {
			return err
		}
	}
	return nil
}

// counterColumns are the additive columns, for the upsert.
var counterColumns = []string{
	"accepted", "authed", "early_close",
	"failed_tls", "failed_auth", "failed_timeout", "failed_reset", "failed_eof", "failed_other", "failed_no_route",
	"failed_quic", "replayed", "follow_up_fail",
	"dur_sum", "dur_n", "rtt_sum", "rtt_n", "retrans_sum", "retrans_n", "up", "down",
}

// UpsertAdd inserts row, or adds its counters into the row already holding
// its cell. timeColumn is "hour" or "day". Written as SQL both SQLite and
// PostgreSQL take: ON CONFLICT … DO UPDATE SET c = t.c + excluded.c.
func UpsertAdd(tx *gorm.DB, row any, timeColumn string) error {
	table := "path_hours"
	if timeColumn == "day" {
		table = "path_days"
	}
	set := map[string]any{}
	for _, c := range counterColumns {
		set[c] = gorm.Expr(table + "." + c + " + excluded." + c)
	}
	cols := []clause.Column{{Name: timeColumn}}
	for _, c := range []string{"node_id", "inbound", "client_asn", "country", "region", "network", "source_kind"} {
		cols = append(cols, clause.Column{Name: c})
	}
	return tx.Clauses(clause.OnConflict{Columns: cols, DoUpdates: clause.Assignments(set)}).Create(row).Error
}

func addTunnelCounters(a, b *model.TunnelCounters) {
	a.Attempts += b.Attempts
	a.Up += b.Up
	a.Flapped += b.Flapped
	a.FailedDial += b.FailedDial
	a.FailedTLS += b.FailedTLS
	a.FailedPreface += b.FailedPreface
	a.FailedRefused += b.FailedRefused
	a.FailedTimeout += b.FailedTimeout
	a.FailedReset += b.FailedReset
	a.FailedEOF += b.FailedEOF
	a.FailedOther += b.FailedOther
	a.LifetimeSum += b.LifetimeSum
	a.LifetimeN += b.LifetimeN
}

// tunnelColumns are a tunnel hour's additive columns.
var tunnelColumns = []string{
	"attempts", "up", "flapped", "failed_dial", "failed_tls", "failed_preface", "failed_refused",
	"failed_timeout", "failed_reset", "failed_eof", "failed_other", "lifetime_sum", "lifetime_n",
}

// upsertTunnel inserts a tunnel hour or adds into the row holding its cell.
func upsertTunnel(tx *gorm.DB, row *model.TunnelHour) error {
	set := map[string]any{}
	for _, c := range tunnelColumns {
		set[c] = gorm.Expr("tunnel_hours." + c + " + excluded." + c)
	}
	cols := []clause.Column{}
	for _, c := range []string{"hour", "node_id", "tunnel", "peer", "server", "side"} {
		cols = append(cols, clause.Column{Name: c})
	}
	return tx.Clauses(clause.OnConflict{Columns: cols, DoUpdates: clause.Assignments(set)}).Create(row).Error
}
