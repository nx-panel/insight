// Package detect decides when a path is degraded and when it recovered.
// A path is one node, inbound, client ASN and network. Its normal is learned per hour of the week — 168
// slots of an exponentially weighted mean and variance — with a fallback to
// the path's recent hours while a slot has seen too few weeks; the last
// fifteen minutes are compared with it every evaluation, and a state moves
// only after two evaluations in a row agree (hysteresis).
//
// When every path of one client ASN with a normal is degraded on two or
// more nodes at once, it is not those paths that are blocked but the ASN
// that is cut off — an Iranian mobile shutdown, a Russian whitelist mode:
// one asn.outage alert, no per-path alerts for it, and the
// subscription hints for it are left as they were.
//
// Every evaluation that judged the window also hands what it judged, on
// this run's evidence only, to OnRead (Reading): Mode B records it for the
// hour.
package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"sort"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/model"
)

// Tunables, constants first.
const (
	// BucketEvery and Buckets make the window compared with the normal.
	BucketEvery = 5 * time.Minute
	Buckets     = 3
	// slotAlpha weighs each new week of an hour-of-week slot; recentAlpha
	// each new hour of the recent normal.
	slotAlpha   = 0.3
	recentAlpha = 0.1
	// A slot is trusted after slotMin weeks, the recent normal after
	// recentMin hours.
	slotMin   = 3
	recentMin = 6
	// A path is judged only with this much traffic in its normal (authed per
	// hour) or in the window (accepted).
	minNormal = 20.0
	minWindow = 10
	// A drop is judged only where the normal expects this many authenticated
	// sessions in the window: at five expected, a quiet quarter of an hour
	// with one or none happens by chance about once in twenty-five
	// (Poisson), which is several false alerts a day per quiet path; at
	// twelve, three or fewer is one in four hundred.
	minExpected = 12.0
	// zBad is the z-score past which a window is bad; the ratio floors keep a
	// quiet path's noise from reading as a block.
	zBad         = 3.0
	failFloor    = 0.5
	earlyFloor   = 0.5
	dropFraction = 0.3
	// confirm is how many evaluations in a row move a state.
	confirm = 2
	// maxWindowKeys bounds one bucket of the window. A bucket that filled
	// says nothing about the paths it has no row for, so while one is in
	// the window a path with no traffic in it is not judged a drop.
	maxWindowKeys = 20000
	// alertsKept is how long an alert is kept.
	alertsKept = 90 * 24 * time.Hour
	// panelKeeps is how long the panel holds samples for a reader that is
	// late (its ring): a feed broken for less than this lost nothing.
	panelKeeps = 15 * time.Minute
	// relearnAfter is how long a path's normal stays frozen while it is
	// degraded. A block is not the path's normal; but a path whose traffic
	// changed for good — its users moved off it, a network that shrank —
	// would otherwise read degraded for ever, with nothing to acknowledge it
	// by. After this the normal learns again and the path recovers by the
	// numbers it now has: a week and some hours later on the recent normal,
	// about two weeks for a path judged by its hour-of-week slots, which
	// learn one week at a time. A block that lasts that long is, by then,
	// what the path is; so is an ASN outage that long, which ends then too.
	relearnAfter = 7 * 24 * time.Hour
)

// OtherASN is model.OtherASN: never observed, folded or judged here.
const OtherASN = model.OtherASN

// Alert kinds.
const (
	KindDegraded  = "path.degraded"
	KindRecovered = "path.recovered"
	KindOutage    = "asn.outage"
	KindOutageEnd = "asn.recovered"
	// KindTunnelDown and KindTunnelUp are a node-to-node tunnel's
	// (internal/tunnels): raised there, stored and sent like these.
	KindTunnelDown   = "tunnel.down"
	KindTunnelUp     = "tunnel.up"
	RecentSlot       = -1
	reasonFailures   = "failures"
	reasonDrop       = "drop"
	reasonEarlyClose = "early_close"
)

// Key is one path.
type Key struct {
	Node    uint
	Inbound string
	ASN     uint32
	Network string
}

// Alert is one state change, stored and sent.
type Alert struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	Kind    string `json:"kind" gorm:"not null;index"`
	NodeID  uint   `json:"nodeId"`
	Inbound string `json:"inbound"`
	ASN     uint32 `json:"asn" gorm:"column:asn"`
	Network string `json:"network"`
	// Tunnel is a tunnel alert's tunnel, by name; NodeID is then its relay.
	Tunnel string `json:"tunnel,omitempty"`
	Reason string `json:"reason"`
	// Detail is the numbers it was judged on, as JSON.
	Detail string `json:"detail"`
	At     int64  `json:"at" gorm:"not null;index"`
}

func (Alert) TableName() string { return "alerts" }

// Baseline is one path's normal for one hour of the week (Slot 0–167), or
// its recent hours (RecentSlot).
type Baseline struct {
	NodeID  uint   `gorm:"primaryKey;autoIncrement:false"`
	Inbound string `gorm:"primaryKey;size:128"`
	ASN     uint32 `gorm:"primaryKey;column:asn;autoIncrement:false"`
	Network string `gorm:"primaryKey;size:4"`
	Slot    int    `gorm:"primaryKey;autoIncrement:false;index"`
	N       int
	// Authed is per hour; Fail and Early are ratios.
	MeanAuthed, VarAuthed float64
	MeanFail, VarFail     float64
	MeanEarly, VarEarly   float64
}

func (Baseline) TableName() string { return "path_baselines" }

// PathState is one degraded path, kept so a restart neither alerts again
// for a path still down nor forgets to say that one came back. A row with
// Network "" and NodeID 0 is an ASN in an outage.
type PathState struct {
	NodeID  uint   `gorm:"primaryKey;autoIncrement:false"`
	Inbound string `gorm:"primaryKey;size:128"`
	ASN     uint32 `gorm:"primaryKey;column:asn;autoIncrement:false"`
	Network string `gorm:"primaryKey;size:4"`
	Alerted bool
	Reason  string
	Since   int64
}

func (PathState) TableName() string { return "path_states" }

// Tables are this package's, for the migration.
func Tables() []any { return []any{&Alert{}, &Baseline{}, &Suspicion{}, &PathState{}} }

type pathState struct {
	degraded bool
	// alerted is whether its degraded alert went out: one held back by an
	// ASN outage gets no recovery alert either.
	alerted bool
	bad     int
	good    int
	reason  string
	since   int64
	// lastBad is when it last read bad or was degraded: an hour that holds
	// it is not folded into the normal, or a block would become the normal
	// and "recover" by itself after a couple of hours.
	lastBad time.Time
	// fresh is whether a window judged since the feed last (re)started
	// read it bad: a state loaded from the last run, or left from before a
	// break in the feed, is not, until a window reads it bad again
	// (Reading). A reload after a failed store keeps it.
	fresh bool
}

// Reading is what one evaluation that judged the window found, on the
// paths it judged and on this run's evidence only: a path the last run
// left degraded, or one degraded before a break in the feed, is in
// Degraded once a window of this feed has read it bad, and an outage needs
// such paths to start and to stay, as the detector's own does.
type Reading struct {
	// At is the evaluation's moment.
	At time.Time
	// Judged are the paths judged at it: with a normal busy enough to
	// judge, on a node counting and back for a window, whatever traffic the
	// window holds. A relay a broken tunnel explains (TunnelDown, and a
	// window after) is left out, paths and all.
	Judged map[Key]bool
	// Degraded are the judged paths degraded at it.
	Degraded map[Key]bool
	// Outages are the client ASNs in an outage at it.
	Outages map[uint32]bool
}

// Detector holds the window and the states.
type Detector struct {
	DB *gorm.DB
	// Send delivers an alert (Telegram); nil stores only.
	Send func(context.Context, Alert)
	Now  func() time.Time
	// TunnelDown, when set, is the nodes a broken tunnel explains: the
	// relays of tunnels with no link (internal/tunnels). Their paths
	// are judged as ever — the hints still move their users to what
	// works — but a path that goes down on one says nothing (the tunnel's
	// own alert does) and is left out of its ASN's outage count, like a
	// path inside an outage; one still down once the tunnel is back is
	// said then.
	TunnelDown func() map[uint]bool
	// OnRead, when set, is handed what each evaluation that judged the
	// window found (Reading), on Evaluate's goroutine and context, outside
	// mu, once the states are stored: an evaluation whose store fails hands
	// nothing over. It holds the next evaluation back while it runs.
	OnRead func(context.Context, Reading)
	// Started is since when the window has been fed without a break: the
	// first poll that worked after the start, or after a poll that did not
	// or a gap in the panel's buffer (Covered, Lost, Gapped). The window covers no more than the time since, and
	// while it is zero nothing is judged: no data is not no traffic.
	Started time.Time

	mu sync.Mutex
	// loaded is whether states and outages were read from the database;
	// seenLoaded whether the last run's stop was accounted for (once).
	loaded     bool
	seenLoaded bool
	// saved is what the database holds of them.
	saved map[Key]PathState
	// overflowed is when a bucket last filled (maxWindowKeys).
	overflowed time.Time
	// blind are the hours samples were lost in: they teach the normals
	// nothing. lostSince is when the feed broke, zero while it runs.
	blind     map[int64]bool
	lostSince time.Time
	// lastFed is when a poll last worked. counting are the nodes the panel
	// listed as counting at it, nil when not known; onAll, per hour, the
	// nodes that counted at every poll of it; backAt when a node last came
	// back, until the window covers it again (Covered). onAll is not
	// stored: across a restart the hours not yet folded read as every node
	// on, so a node off in them folds a silent hour into its paths' normals
	// — less sensitive for a while, never an alert.
	lastFed  time.Time
	counting map[uint]bool
	onAll    map[int64]map[uint]bool
	backAt   map[uint]time.Time
	buckets  [Buckets]map[Key]*model.PathCounters
	start    time.Time // the newest bucket's start
	states   map[Key]*pathState
	outages  map[uint32]bool
	// readOutages are the outages the last Reading held, for the half that
	// keeps one there; a break in the feed clears them (stale).
	readOutages map[uint32]bool
	// baselined is the last hour folded into the normals.
	baselined int64
	// tunnelSeen is when each node was last held for a broken tunnel
	// (TunnelDown): its held paths are not said until a window has passed
	// since, or the window still full of the cut would speak for them.
	tunnelSeen map[uint]time.Time
}

func (d *Detector) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Covered says a poll of the panel worked: the window is being fed.
// counting are the nodes the panel lists as counting now, nil when it did
// not say; every other node — switched off, unreachable, too old, a wrong
// clock, or deleted from the panel — is not counting, and its silence is no
// block.
func (d *Detector) Covered(counting map[uint]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.lastFed = now
	if d.Started.IsZero() {
		d.Started = now
	}
	// A feed that was broken for less than the panel keeps lost nothing:
	// the next poll brought it all. Longer, and the hours it spans are short
	// of what happened.
	if !d.lostSince.IsZero() {
		if now.Sub(d.lostSince) >= panelKeeps {
			d.markBlind(d.lostSince, now)
		}
		d.lostSince = time.Time{}
	}
	if counting == nil {
		return
	}
	// onAll is, per hour, the nodes that counted at every poll of it: a node
	// missing from it was off for some of that hour, which is not its
	// paths' normal.
	hour := now.Truncate(time.Hour).Unix()
	if d.onAll == nil {
		d.onAll = map[int64]map[uint]bool{}
	}
	if have, ok := d.onAll[hour]; !ok {
		d.onAll[hour] = maps.Clone(counting)
	} else {
		for n := range have {
			if !counting[n] {
				delete(have, n)
			}
		}
	}
	for h := range d.onAll {
		if h < hour-48*3600 {
			delete(d.onAll, h)
		}
	}
	// A node that comes back is judged once the window covers it again.
	if d.counting != nil {
		for n := range counting {
			if !d.counting[n] {
				if d.backAt == nil {
					d.backAt = map[uint]time.Time{}
				}
				d.backAt[n] = now
				delete(d.onAll[hour], n) // the hour it came back in is one it was off in
			}
		}
		for n := range d.backAt {
			if !counting[n] {
				delete(d.backAt, n)
			}
		}
	}
	d.counting = counting
}

// off is whether node is known not to be counting. The caller holds mu.
func (d *Detector) off(node uint) bool { return d.counting != nil && !d.counting[node] }

// Lost says a poll failed or was not made: nothing is judged until the feed
// has run unbroken for a bucket again — no data is not no traffic.
func (d *Detector) Lost() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.lostSince.IsZero() {
		d.lostSince = d.now()
	}
	d.Started = time.Time{}
	d.buckets = [Buckets]map[Key]*model.PathCounters{}
	d.stale()
}

// stale marks every state as not read in the current feed. The caller
// holds mu.
func (d *Detector) stale() {
	for _, st := range d.states {
		st.fresh = false
	}
	d.readOutages = nil
}

// Gapped says the panel dropped samples before they were read: what the
// window and the stored hours hold of the last panelKeeps is short.
func (d *Detector) Gapped() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	d.Started = time.Time{}
	d.buckets = [Buckets]map[Key]*model.PathCounters{}
	d.stale()
	d.markBlind(now.Add(-panelKeeps), now)
}

// markBlind notes the hours from..to as ones the normals must not learn
// from (at most the eight days the hourly rows are kept). The caller holds
// mu.
func (d *Detector) markBlind(from, to time.Time) {
	if d.blind == nil {
		d.blind = map[int64]bool{}
	}
	if oldest := to.Add(-8 * 24 * time.Hour); from.Before(oldest) {
		from = oldest
	}
	for h := from.Truncate(time.Hour); !h.After(to); h = h.Add(time.Hour) {
		d.blind[h.Unix()] = true
	}
	for h := range d.blind {
		if h < to.Add(-9*24*time.Hour).Unix() {
			delete(d.blind, h)
		}
	}
}

// Observe adds a polled sample's counters to the window.
func (d *Detector) Observe(k Key, c model.PathCounters) {
	if k.ASN == OtherASN {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rotate(d.now())
	b := d.buckets[0]
	if b == nil {
		b = map[Key]*model.PathCounters{}
		d.buckets[0] = b
	}
	have := b[k]
	if have == nil {
		if len(b) >= maxWindowKeys {
			d.overflowed = d.now()
			return
		}
		have = &model.PathCounters{}
		b[k] = have
	}
	have.Accepted += c.Accepted
	have.Authed += c.Authed
	have.EarlyClose += c.EarlyClose
	have.FailedAuth += c.FailedAuth + c.FailedTLS + c.FailedTimeout + c.FailedReset + c.FailedEOF + c.FailedOther
}

// rotate moves the window to now. The caller holds mu.
func (d *Detector) rotate(now time.Time) {
	cur := now.Truncate(BucketEvery)
	if d.start.IsZero() {
		d.start = cur
		return
	}
	for steps := 0; d.start.Before(cur) && steps < Buckets; steps++ {
		copy(d.buckets[1:], d.buckets[:Buckets-1])
		d.buckets[0] = nil
		d.start = d.start.Add(BucketEvery)
	}
	if d.start.Before(cur) {
		d.buckets = [Buckets]map[Key]*model.PathCounters{}
		d.start = cur
	}
}

// Recent is the window's counters per path — the last Buckets×BucketEvery,
// every failure in FailedAuth — for the metrics. A path of the folded ASN
// is not in it.
func (d *Detector) Recent() map[Key]model.PathCounters {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rotate(d.now())
	return d.window()
}

func (d *Detector) window() map[Key]model.PathCounters {
	out := map[Key]model.PathCounters{}
	for _, b := range d.buckets {
		for k, c := range b {
			w := out[k]
			w.Accepted += c.Accepted
			w.Authed += c.Authed
			w.EarlyClose += c.EarlyClose
			w.FailedAuth += c.FailedAuth
			out[k] = w
		}
	}
	return out
}

// SlotOf is t's hour of the week, 0 = Monday 00:00 UTC.
func SlotOf(t time.Time) int {
	t = t.UTC()
	return (int(t.Weekday())+6)%7*24 + t.Hour()
}

// load reads the degraded paths and outages a previous run left, and when
// that run was last fed: a stop longer than the panel keeps samples left
// hours that are short of what happened.
func (d *Detector) load(ctx context.Context, now time.Time) error {
	var rows []PathState
	tx := d.DB.WithContext(ctx)
	if err := tx.Find(&rows).Error; err != nil {
		return err
	}
	var seen model.State
	if err := tx.Where("key = ?", stateSeen).Limit(1).Find(&seen).Error; err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.loaded {
		return nil
	}
	prev := d.states // a reload after a failed store keeps what was read
	d.states, d.outages, d.saved = map[Key]*pathState{}, map[uint32]bool{}, map[Key]PathState{}
	for _, r := range rows {
		k := Key{r.NodeID, r.Inbound, r.ASN, r.Network}
		d.saved[k] = r
		if r.NodeID == 0 && r.Network == "" {
			d.outages[r.ASN] = true
			continue
		}
		// It was down when Insight stopped: it stays down until two good
		// evaluations say otherwise, and the hours since are not its normal.
		d.states[k] = &pathState{degraded: true, alerted: r.Alerted, reason: r.Reason, since: r.Since, lastBad: now, fresh: prev[k] != nil && prev[k].fresh}
	}
	if !d.seenLoaded {
		// From the last poll that worked before the stop to the first one
		// after the start: the stop itself. The value is written with the
		// evaluations, up to a flush late, so it is given that much slack.
		var at int64
		first := d.Started
		if first.IsZero() {
			first = now
		}
		if _, err := fmt.Sscan(seen.Value, &at); err == nil && at > 0 {
			if last := time.Unix(at, 0); first.Sub(last) >= panelKeeps+BucketEvery {
				d.markBlind(last, first)
			}
		}
		d.seenLoaded = true
	}
	d.loaded = true
	return nil
}

// stateSeen is when a poll last worked, as of the last evaluation.
const stateSeen = "detect_seen"

// Evaluate folds finished hours into the normals, judges every path with a
// normal against the window, raises the alerts the changes make and, when
// it judged, hands what it found to OnRead.
func (d *Detector) Evaluate(ctx context.Context) error {
	now := d.now()
	tunnelDown := map[uint]bool{}
	if d.TunnelDown != nil {
		if m := d.TunnelDown(); m != nil {
			tunnelDown = m
		}
	}
	d.mu.Lock()
	if d.tunnelSeen == nil {
		d.tunnelSeen = map[uint]time.Time{}
	}
	for n := range tunnelDown {
		d.tunnelSeen[n] = now
	}
	for n, at := range d.tunnelSeen {
		if now.Sub(at) >= time.Duration(Buckets)*BucketEvery {
			delete(d.tunnelSeen, n)
		}
	}
	d.mu.Unlock()
	// The states first: an hour a path was down in must not be folded
	// because a restart came between.
	d.mu.Lock()
	loaded, fed := d.loaded, d.lastFed
	d.mu.Unlock()
	if !loaded {
		if err := d.load(ctx, now); err != nil {
			return err
		}
	}
	if !fed.IsZero() {
		if err := model.PutState(d.DB.WithContext(ctx), stateSeen, fmt.Sprint(fed.Unix())); err != nil {
			return err
		}
	}
	if err := d.foldHours(ctx, now); err != nil {
		return err
	}
	var baselines []Baseline
	if err := d.DB.WithContext(ctx).Where("slot IN ?", []int{SlotOf(now), RecentSlot}).Find(&baselines).Error; err != nil {
		return err
	}
	// The hour-of-week normal once it has seen slotMin weeks, the recent
	// one until then.
	slotNormals, recentNormals := map[Key]Baseline{}, map[Key]Baseline{}
	known := map[Key]bool{}
	for _, b := range baselines {
		k := Key{b.NodeID, b.Inbound, b.ASN, b.Network}
		known[k] = true
		switch {
		case b.Slot == RecentSlot && b.N >= recentMin:
			recentNormals[k] = b
		case b.Slot != RecentSlot && b.N >= slotMin:
			slotNormals[k] = b
		}
	}
	normals := recentNormals
	for k, b := range slotNormals {
		normals[k] = b
	}
	d.mu.Lock()
	d.rotate(now)
	win := d.window()
	// How much time the window holds: a full one, or what has passed since
	// the feed last (re)started — a rate read over the full span would make
	// every path look like it dropped. Under one bucket, or with no feed at
	// all, nothing is judged: the states stay as they are.
	if d.Started.IsZero() {
		d.mu.Unlock()
		return nil
	}
	span := time.Duration(Buckets) * BucketEvery
	if covered := now.Sub(d.Started); covered < BucketEvery {
		d.mu.Unlock()
		return nil
	} else if covered < span {
		span = covered
	}
	overflowed := !d.overflowed.IsZero() && now.Sub(d.overflowed) < time.Duration(Buckets)*BucketEvery
	// A path whose every normal is gone (pruned: no traffic for a week, its
	// node or inbound removed) is forgotten without a word.
	for k := range d.states {
		if !known[k] {
			delete(d.states, k)
		}
	}
	var alerts []Alert
	type asnView struct {
		paths, degraded int
		nodes           map[uint]bool
		// judged, fresh and judgedNodes are the Reading's: the paths judged
		// now, those of them degraded on this feed's evidence, their nodes.
		judged, fresh int
		judgedNodes   map[uint]bool
	}
	judged := map[Key]bool{}
	byASN := map[uint32]*asnView{}
	keys := make([]Key, 0, len(normals))
	for k := range normals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	// present are the ASNs that still have a normal, judged this time or
	// not.
	present := map[uint32]bool{}
	type change struct {
		k      Key
		to     bool
		reason string
		detail map[string]float64
	}
	var changes []change
	at := now.Unix()
	for _, k := range keys {
		b := normals[k]
		if k.ASN == OtherASN {
			continue
		}
		present[k.ASN] = true
		st := d.states[k]
		if st != nil && st.degraded {
			st.lastBad = now
		}
		// A node that is not counting sends nothing: that is not a block.
		// Its paths keep their state and are left out of the ASN's count —
		// and so are those of a node that came back less than a window
		// ago, whose window is still mostly the silence before.
		if d.off(k.Node) {
			continue
		}
		if back, ok := d.backAt[k.Node]; ok {
			if now.Sub(back) < time.Duration(Buckets)*BucketEvery {
				continue
			}
			delete(d.backAt, k.Node)
		}
		view := func() *asnView {
			v := byASN[k.ASN]
			if v == nil {
				v = &asnView{nodes: map[uint]bool{}, judgedNodes: map[uint]bool{}}
				byASN[k.ASN] = v
			}
			return v
		}
		if b.MeanAuthed < minNormal {
			// Too quiet at this hour to judge; a path already down still
			// counts as down for its ASN.
			if st != nil && st.degraded && !tunnelDown[k.Node] {
				v := view()
				v.paths++
				v.degraded++
				v.nodes[k.Node] = true
			}
			continue
		}
		w, seen := win[k]
		bad, reason, detail := judge(b, w, span)
		if bad && reason == reasonDrop && overflowed && !seen {
			bad = false // the window could not hold it: unknown, not a drop
		}
		if st == nil {
			st = &pathState{}
			d.states[k] = st
		}
		if bad {
			st.bad, st.good, st.fresh = st.bad+1, 0, true
			if !st.degraded && st.bad >= confirm {
				st.degraded, st.reason, st.since, st.lastBad = true, reason, at, now
				changes = append(changes, change{k, true, reason, detail})
			}
		} else {
			st.good, st.bad = st.good+1, 0
			if st.degraded && st.good >= confirm {
				st.degraded = false
				changes = append(changes, change{k, false, st.reason, detail})
			}
		}
		if tunnelDown[k.Node] {
			continue // the tunnel explains it: no evidence about the ASN
		}
		v := view()
		v.paths++
		v.nodes[k.Node] = true
		if st.degraded {
			v.degraded++
		}
		if _, held := d.tunnelSeen[k.Node]; held {
			continue // back for less than a window: the cut is still in it
		}
		judged[k] = true
		v.judged++
		v.judgedNodes[k.Node] = true
		if st.degraded && st.fresh {
			v.fresh++
		}
	}
	asns := make([]uint32, 0, len(byASN))
	for a := range byASN {
		asns = append(asns, a)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	for _, asn := range asns {
		v := byASN[asn]
		out := len(v.nodes) >= 2 && v.degraded == v.paths
		switch {
		case out && !d.outages[asn]:
			d.outages[asn] = true
			alerts = append(alerts, Alert{Kind: KindOutage, ASN: asn, At: at, Detail: detailJSON(map[string]float64{"paths": float64(v.paths), "nodes": float64(len(v.nodes))})})
		case !out && d.outages[asn] && v.degraded*2 < v.paths:
			delete(d.outages, asn)
			alerts = append(alerts, Alert{Kind: KindOutageEnd, ASN: asn, At: at})
		}
	}
	// An outage whose ASN has no normal left (pruned) has nothing to end it:
	// it ends here. One whose paths were only not judged this time — their
	// nodes are off — stays.
	for asn := range d.outages {
		if !present[asn] {
			delete(d.outages, asn)
			alerts = append(alerts, Alert{Kind: KindOutageEnd, ASN: asn, At: at})
		}
	}
	changed := map[Key]bool{}
	for _, c := range changes {
		changed[c.k] = true
		st := d.states[c.k]
		_, tunneled := d.tunnelSeen[c.k.Node]
		if c.to && (d.outages[c.k.ASN] || tunneled) {
			continue // the ASN's or the tunnel's own alert says it
		}
		if !c.to && !st.alerted {
			continue // its going down was never said either
		}
		st.alerted = c.to
		kind := KindRecovered
		if c.to {
			kind = KindDegraded
		}
		alerts = append(alerts, Alert{
			Kind: kind, NodeID: c.k.Node, Inbound: c.k.Inbound, ASN: c.k.ASN, Network: c.k.Network,
			Reason: c.reason, At: at, Detail: detailJSON(c.detail),
		})
	}
	// A path down and never said — an outage or a broken tunnel spoke for
	// it — whose ASN is back and whose tunnel has worked for a window, and
	// which still reads bad: it is said now. One reading good is on its way back with the
	// rest and says nothing. This holds across a restart too, which forgets
	// which tunnels were down but keeps which paths were not alerted.
	for _, k := range keys {
		st := d.states[k]
		if st == nil || !st.degraded || st.alerted || st.bad == 0 || changed[k] || d.outages[k.ASN] || d.off(k.Node) {
			continue
		}
		if _, held := d.tunnelSeen[k.Node]; held {
			continue // the tunnel is down, or back for less than a window
		}
		st.alerted = true
		alerts = append(alerts, Alert{
			Kind: KindDegraded, NodeID: k.Node, Inbound: k.Inbound, ASN: k.ASN, Network: k.Network,
			Reason: st.reason, At: at, Detail: detailJSON(map[string]float64{"normalAuthedPerHour": normals[k].MeanAuthed}),
		})
	}
	// What this evaluation found, on the paths it judged and this feed's
	// evidence. An outage there follows the detector's rules on those
	// paths alone: every one degraded on two nodes or more to start, half
	// of them to stay in one the last Reading held.
	reading := Reading{At: now, Judged: judged, Degraded: map[Key]bool{}, Outages: map[uint32]bool{}}
	for k := range judged {
		if st := d.states[k]; st != nil && st.degraded && st.fresh {
			reading.Degraded[k] = true
		}
	}
	for asn := range d.outages {
		v := byASN[asn]
		if v == nil || v.judged == 0 {
			continue
		}
		start := len(v.judgedNodes) >= 2 && v.fresh == v.judged
		stay := d.readOutages[asn] && v.fresh*2 >= v.judged
		if start || stay {
			reading.Outages[asn] = true
		}
	}
	// What the database must hold now, against what it holds.
	want := map[Key]PathState{}
	for k, st := range d.states {
		if st.degraded {
			want[k] = PathState{NodeID: k.Node, Inbound: k.Inbound, ASN: k.ASN, Network: k.Network, Alerted: st.alerted, Reason: st.reason, Since: st.since}
		} else if st.bad == 0 && now.Sub(st.lastBad) > 2*time.Hour {
			delete(d.states, k) // nothing left to remember about a healthy path
		}
	}
	for asn := range d.outages {
		k := Key{ASN: asn}
		row, ok := d.saved[k]
		if !ok {
			row = PathState{ASN: asn, Since: at}
		}
		want[k] = row
	}
	var put []PathState
	var drop []Key
	for k, row := range want {
		if d.saved[k] != row {
			put = append(put, row)
		}
	}
	for k := range d.saved {
		if _, ok := want[k]; !ok {
			drop = append(drop, k)
		}
	}
	d.mu.Unlock()
	if len(alerts) == 0 && len(put) == 0 && len(drop) == 0 {
		d.handOver(ctx, reading)
		return nil
	}
	// The states and their alerts are written together: an alert that could
	// not be stored must not leave a state that says it was.
	err := d.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, k := range drop {
			if err := tx.Where("node_id = ? AND inbound = ? AND asn = ? AND network = ?", k.Node, k.Inbound, k.ASN, k.Network).Delete(&PathState{}).Error; err != nil {
				return err
			}
		}
		if len(put) > 0 {
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).CreateInBatches(put, 200).Error; err != nil {
				return err
			}
		}
		for i := range alerts {
			if err := tx.Create(&alerts[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
	d.mu.Lock()
	if err != nil {
		d.loaded = false // back to what the database holds
		d.mu.Unlock()
		return err
	}
	d.saved = want
	d.mu.Unlock()
	if d.Send != nil {
		for i := range alerts {
			d.Send(ctx, alerts[i])
		}
	}
	d.handOver(ctx, reading)
	return nil
}

// handOver keeps r's outages for the next Reading and gives r to OnRead.
func (d *Detector) handOver(ctx context.Context, r Reading) {
	d.mu.Lock()
	d.readOutages = maps.Clone(r.Outages)
	d.mu.Unlock()
	if d.OnRead != nil {
		d.OnRead(ctx, r)
	}
}

// judge compares a window with a path's normal.
func judge(b Baseline, w model.PathCounters, span time.Duration) (bool, string, map[string]float64) {
	perHour := float64(w.Authed) * float64(time.Hour) / float64(span)
	detail := map[string]float64{"authedPerHour": perHour, "normalAuthedPerHour": b.MeanAuthed}
	if w.Accepted >= minWindow {
		fail := float64(w.FailedAuth) / float64(w.Accepted)
		detail["failRatio"], detail["normalFailRatio"] = fail, b.MeanFail
		if fail >= failFloor && z(fail, b.MeanFail, b.VarFail, 0.05) >= zBad {
			return true, reasonFailures, detail
		}
	}
	expected := b.MeanAuthed * float64(span) / float64(time.Hour)
	if expected >= minExpected && perHour <= dropFraction*b.MeanAuthed && z(perHour, b.MeanAuthed, b.VarAuthed, math.Sqrt(b.MeanAuthed)) <= -zBad {
		return true, reasonDrop, detail
	}
	if w.Authed >= minWindow {
		early := float64(w.EarlyClose) / float64(w.Authed)
		detail["earlyRatio"], detail["normalEarlyRatio"] = early, b.MeanEarly
		if early >= earlyFloor && z(early, b.MeanEarly, b.VarEarly, 0.05) >= zBad {
			return true, reasonEarlyClose, detail
		}
	}
	return false, "", detail
}

// z is x's distance from the mean in standard deviations, the deviation
// floored so a path that never varied is not alarmed by one connection.
func z(x, mean, variance, floor float64) float64 {
	sd := math.Max(math.Sqrt(math.Max(variance, 0)), floor)
	if sd == 0 {
		return 0
	}
	return (x - mean) / sd
}

func less(a, b Key) bool {
	if a.Node != b.Node {
		return a.Node < b.Node
	}
	if a.Inbound != b.Inbound {
		return a.Inbound < b.Inbound
	}
	if a.ASN != b.ASN {
		return a.ASN < b.ASN
	}
	return a.Network < b.Network
}

func detailJSON(m map[string]float64) string {
	raw, _ := json.Marshal(m)
	return string(raw)
}

// foldHours updates the normals with every hour that is complete and
// flushed (an hour is complete one flush after it ends) and not folded yet.
func (d *Detector) foldHours(ctx context.Context, now time.Time) error {
	ready := now.Add(-time.Hour - 6*time.Minute).Truncate(time.Hour).Unix()
	d.mu.Lock()
	from := d.baselined
	d.mu.Unlock()
	if from == 0 {
		var st model.State
		if err := d.DB.WithContext(ctx).Where("key = ?", stateBaselined).Limit(1).Find(&st).Error; err != nil {
			return err
		}
		if st.Value != "" {
			if _, err := fmt.Sscan(st.Value, &from); err != nil {
				from = 0 // a damaged row: start from the hour now finishing
			}
		}
		if from == 0 {
			from = ready - 3600
		}
	}
	for hour := from + 3600; hour <= ready; hour += 3600 {
		if err := d.foldHour(ctx, hour); err != nil {
			return err
		}
		from = hour
	}
	d.mu.Lock()
	d.baselined = from
	d.mu.Unlock()
	return nil
}

const stateBaselined = "baselined_through"

type hourRow struct {
	NodeID     uint
	Inbound    string
	ClientASN  uint32
	Network    string
	Accepted   uint64
	Authed     uint64
	EarlyClose uint64
	Failed     uint64
}

func (d *Detector) foldHour(ctx context.Context, hour int64) error {
	d.mu.Lock()
	blind := d.blind[hour]
	frozen := map[Key]bool{}
	for k, st := range d.states {
		if !st.lastBad.IsZero() && st.lastBad.Unix() >= hour && hour-st.since < int64(relearnAfter/time.Second) {
			frozen[k] = true
		}
	}
	on, known := d.onAll[hour]
	offIn := func(n uint) bool { return known && !on[n] }
	d.mu.Unlock()
	mark := func(tx *gorm.DB) error { return model.PutState(tx, stateBaselined, fmt.Sprint(hour)) }
	if blind {
		// The feed was broken for part of it: what was stored is less than
		// what happened, and would be learned as a quiet hour.
		return mark(d.DB.WithContext(ctx))
	}
	var rows []hourRow
	err := d.DB.WithContext(ctx).Model(&model.PathHour{}).
		Select("node_id, inbound, client_asn, network, SUM(accepted) AS accepted, SUM(authed) AS authed, SUM(early_close) AS early_close, "+
			"SUM(failed_tls + failed_auth + failed_timeout + failed_reset + failed_eof + failed_other) AS failed").
		Where("hour = ? AND client_asn <> ?", hour, OtherASN).Group("node_id, inbound, client_asn, network").Scan(&rows).Error
	if err != nil {
		return err
	}
	slot := SlotOf(time.Unix(hour, 0))
	return d.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// A path with a normal and no traffic in an hour that has traffic
		// elsewhere has a zero hour: a block that stopped everything must
		// count. An hour with no row at all is an hour Insight was not
		// collecting (or the whole fleet was dark), and teaches nothing.
		var known []Baseline
		if len(rows) > 0 {
			if err := tx.Where("slot = ?", RecentSlot).Find(&known).Error; err != nil {
				return err
			}
		}
		seen := map[Key]bool{}
		obs := map[Key]hourRow{}
		for _, r := range rows {
			k := Key{r.NodeID, r.Inbound, r.ClientASN, r.Network}
			obs[k], seen[k] = r, true
		}
		for _, b := range known {
			k := Key{b.NodeID, b.Inbound, b.ASN, b.Network}
			if !seen[k] && k.ASN != OtherASN {
				obs[k] = hourRow{NodeID: k.Node, Inbound: k.Inbound, ClientASN: k.ASN, Network: k.Network}
			}
		}
		for k, r := range obs {
			// Not an hour its node was off in for any part: what it counted
			// then, or did not, is the node's silence and not the path's.
			if offIn(k.Node) {
				continue
			}
			// An hour a path was bad in is not its normal: learned, a block
			// would pull the mean down and the variance up until the block
			// itself read as normal and "recovered" two hours in.
			if frozen[k] {
				continue
			}
			for _, s := range []struct {
				slot  int
				alpha float64
			}{{slot, slotAlpha}, {RecentSlot, recentAlpha}} {
				b := Baseline{NodeID: k.Node, Inbound: k.Inbound, ASN: k.ASN, Network: k.Network, Slot: s.slot}
				// Spelled out: a struct condition drops zero fields, and slot 0
				// and ASN 0 are real values here.
				if err := tx.Where("node_id = ? AND inbound = ? AND asn = ? AND network = ? AND slot = ?",
					k.Node, k.Inbound, k.ASN, k.Network, s.slot).Limit(1).Find(&b).Error; err != nil {
					return err
				}
				update(&b, r, s.alpha)
				if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&b).Error; err != nil {
					return err
				}
			}
		}
		return mark(tx)
	})
}

// Prune forgets what nothing will read again: the normals of a path with no
// stored hour left (seven days without a connection — its node or inbound
// removed, or its network gone), the probe history of an endpoint with none,
// and alerts past alertsKept.
//
// Only once the stored hours reach seven days back, the week they are kept
// for (Compact keeps them to UTC midnight seven days ago, so a running feed
// always does). They age out by the clock whether or not anything is
// polled, so after a week without a feed — the panel down, the token revoked
// — every path would look gone, and normals that took weeks to learn would go
// with them, both while the feed is down and in the first week after it is
// back.
func (d *Detector) Prune(ctx context.Context) error {
	tx := d.DB.WithContext(ctx)
	now := d.now()
	if err := tx.Where("at < ?", now.Add(-alertsKept).Unix()).Delete(&Alert{}).Error; err != nil {
		return err
	}
	var fresh, old []model.PathHour
	if err := tx.Select("id").Where("hour >= ?", now.Add(-24*time.Hour).Unix()).Limit(1).Find(&fresh).Error; err != nil || len(fresh) == 0 {
		return err
	}
	if err := tx.Select("id").Where("hour <= ?", now.Add(-7*24*time.Hour).Unix()).Limit(1).Find(&old).Error; err != nil || len(old) == 0 {
		return err
	}
	// One pass over the stored hours for the paths that still have one, then
	// the stale ones by key: a correlated delete has no index to walk
	// path_hours by and held the write lock for its whole scan.
	var live []struct {
		NodeID    uint
		Inbound   string
		ClientASN uint32
		Network   string
	}
	if err := tx.Model(&model.PathHour{}).Distinct("node_id", "inbound", "client_asn", "network").Scan(&live).Error; err != nil {
		return err
	}
	paths, endpoints := map[Key]bool{}, map[Endpoint]bool{}
	for _, r := range live {
		paths[Key{r.NodeID, r.Inbound, r.ClientASN, r.Network}] = true
		endpoints[Endpoint{r.NodeID, r.Inbound}] = true
	}
	var known []Baseline
	if err := tx.Select("node_id", "inbound", "asn", "network").Where("slot = ?", RecentSlot).Find(&known).Error; err != nil {
		return err
	}
	for _, b := range known {
		if paths[Key{b.NodeID, b.Inbound, b.ASN, b.Network}] {
			continue
		}
		if err := tx.Where("node_id = ? AND inbound = ? AND asn = ? AND network = ?", b.NodeID, b.Inbound, b.ASN, b.Network).
			Delete(&Baseline{}).Error; err != nil {
			return err
		}
	}
	var held []Suspicion
	if err := tx.Select("node_id", "inbound").Find(&held).Error; err != nil {
		return err
	}
	for _, sus := range held {
		if endpoints[Endpoint{sus.NodeID, sus.Inbound}] {
			continue
		}
		if err := tx.Where("node_id = ? AND inbound = ?", sus.NodeID, sus.Inbound).Delete(&Suspicion{}).Error; err != nil {
			return err
		}
	}
	return nil
}

// update moves a normal toward one observed hour.
func update(b *Baseline, r hourRow, alpha float64) {
	authed := float64(r.Authed)
	fail, early := 0.0, 0.0
	if r.Accepted > 0 {
		fail = float64(r.Failed) / float64(r.Accepted)
	}
	if r.Authed > 0 {
		early = float64(r.EarlyClose) / float64(r.Authed)
	}
	if b.N == 0 {
		b.MeanAuthed, b.MeanFail, b.MeanEarly = authed, fail, early
		b.N = 1
		return
	}
	ewma(&b.MeanAuthed, &b.VarAuthed, authed, alpha)
	ewma(&b.MeanFail, &b.VarFail, fail, alpha)
	ewma(&b.MeanEarly, &b.VarEarly, early, alpha)
	b.N++
}

func ewma(mean, variance *float64, x, alpha float64) {
	diff := x - *mean
	*mean += alpha * diff
	*variance = (1 - alpha) * (*variance + alpha*diff*diff)
}

// Outages are the client ASNs in an outage now.
func (d *Detector) Outages() map[uint32]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[uint32]bool, len(d.outages))
	for a := range d.outages {
		out[a] = true
	}
	return out
}

// Degraded are the paths degraded now.
func (d *Detector) Degraded() map[Key]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[Key]bool{}
	for k, s := range d.states {
		if s.degraded {
			out[k] = true
		}
	}
	return out
}
