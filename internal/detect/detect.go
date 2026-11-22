// Package detect decides when a path is degraded and when it recovered
// (nx-panel docs/path-telemetry.md §4.4, PT5). A path is one node, inbound,
// client ASN and network. Its normal is learned per hour of the week — 168
// slots of an exponentially weighted mean and variance — with a fallback to
// the path's recent hours while a slot has seen too few weeks; the last
// fifteen minutes are compared with it every evaluation, and a state moves
// only after two evaluations in a row agree (hysteresis).
//
// When every path of one client ASN with a normal is degraded on two or
// more nodes at once, it is not those paths that are blocked but the ASN
// that is cut off — an Iranian mobile shutdown, a Russian whitelist mode
// (P20 a): one asn.outage alert, no per-path alerts for it, and the
// subscription hints for it are left as they were.
package detect

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/nx-panel/insight/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Tunables, constants first (decision 7 spirit).
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
	// zBad is the z-score past which a window is bad; the ratio floors keep a
	// quiet path's noise from reading as a block.
	zBad         = 3.0
	failFloor    = 0.5
	earlyFloor   = 0.5
	dropFraction = 0.3
	// confirm is how many evaluations in a row move a state.
	confirm = 2
	// maxWindowKeys bounds the window: past it, paths with no normal are
	// not kept.
	maxWindowKeys = 20000
)

// Alert kinds.
const (
	KindDegraded     = "path.degraded"
	KindRecovered    = "path.recovered"
	KindOutage       = "asn.outage"
	KindOutageEnd    = "asn.recovered"
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
	Reason  string `json:"reason"`
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
	Slot    int    `gorm:"primaryKey;autoIncrement:false"`
	N       int
	// Authed is per hour; Fail and Early are ratios.
	MeanAuthed, VarAuthed float64
	MeanFail, VarFail     float64
	MeanEarly, VarEarly   float64
}

func (Baseline) TableName() string { return "path_baselines" }

// Tables are this package's, for the migration.
func Tables() []any { return []any{&Alert{}, &Baseline{}, &Suspicion{}} }

type pathState struct {
	degraded bool
	// alerted is whether its degraded alert went out: one held back by an
	// ASN outage gets no recovery alert either.
	alerted bool
	bad     int
	good    int
	reason  string
}

// Detector holds the window and the states.
type Detector struct {
	DB *gorm.DB
	// Send delivers an alert (Telegram); nil stores only.
	Send func(context.Context, Alert)
	Now  func() time.Time
	// Started is when Insight began watching: the window covers no more
	// than the time since. Zero is the first Observe or Evaluate.
	Started time.Time

	mu      sync.Mutex
	buckets [Buckets]map[Key]*model.PathCounters
	start   time.Time // the newest bucket's start
	states  map[Key]*pathState
	outages map[uint32]bool
	// baselined is the last hour folded into the normals.
	baselined int64
}

func (d *Detector) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Observe adds a polled sample's counters to the window.
func (d *Detector) Observe(k Key, c model.PathCounters) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.Started.IsZero() {
		d.Started = d.now()
	}
	d.rotate(d.now())
	b := d.buckets[0]
	if b == nil {
		b = map[Key]*model.PathCounters{}
		d.buckets[0] = b
	}
	have := b[k]
	if have == nil {
		if len(b) >= maxWindowKeys {
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

// Evaluate folds finished hours into the normals, judges every path with a
// normal against the window, and raises the alerts the changes make.
func (d *Detector) Evaluate(ctx context.Context) error {
	now := d.now()
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
	for _, b := range baselines {
		k := Key{b.NodeID, b.Inbound, b.ASN, b.Network}
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
	// Insight started — after a restart a rate read over the full span
	// would make every path look like it dropped. Under one bucket, nothing
	// is judged yet.
	if d.Started.IsZero() {
		d.Started = now
	}
	span := time.Duration(Buckets) * BucketEvery
	if covered := now.Sub(d.Started); covered < BucketEvery {
		d.mu.Unlock()
		return nil
	} else if covered < span {
		span = covered
	}
	if d.states == nil {
		d.states = map[Key]*pathState{}
	}
	if d.outages == nil {
		d.outages = map[uint32]bool{}
	}
	var alerts []Alert
	type asnView struct {
		paths, degraded int
		nodes           map[uint]bool
	}
	byASN := map[uint32]*asnView{}
	keys := make([]Key, 0, len(normals))
	for k := range normals {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return less(keys[i], keys[j]) })
	type change struct {
		k      Key
		to     bool
		reason string
		detail map[string]float64
	}
	var changes []change
	for _, k := range keys {
		b := normals[k]
		if b.MeanAuthed < minNormal {
			continue
		}
		w := win[k]
		bad, reason, detail := judge(b, w, span)
		st := d.states[k]
		if st == nil {
			st = &pathState{}
			d.states[k] = st
		}
		if bad {
			st.bad, st.good = st.bad+1, 0
			if !st.degraded && st.bad >= confirm {
				st.degraded, st.reason = true, reason
				changes = append(changes, change{k, true, reason, detail})
			}
		} else {
			st.good, st.bad = st.good+1, 0
			if st.degraded && st.good >= confirm {
				st.degraded = false
				changes = append(changes, change{k, false, st.reason, detail})
			}
		}
		v := byASN[k.ASN]
		if v == nil {
			v = &asnView{nodes: map[uint]bool{}}
			byASN[k.ASN] = v
		}
		v.paths++
		v.nodes[k.Node] = true
		if st.degraded {
			v.degraded++
		}
	}
	at := now.Unix()
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
	for _, c := range changes {
		st := d.states[c.k]
		if c.to && d.outages[c.k.ASN] {
			continue // the ASN's own alert says it
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
	d.mu.Unlock()
	for i := range alerts {
		if err := d.DB.WithContext(ctx).Create(&alerts[i]).Error; err != nil {
			return err
		}
		if d.Send != nil {
			d.Send(ctx, alerts[i])
		}
	}
	return nil
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
	if perHour <= dropFraction*b.MeanAuthed && z(perHour, b.MeanAuthed, b.VarAuthed, math.Sqrt(b.MeanAuthed)) <= -zBad {
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
	var rows []hourRow
	err := d.DB.WithContext(ctx).Model(&model.PathHour{}).
		Select("node_id, inbound, client_asn, network, SUM(accepted) AS accepted, SUM(authed) AS authed, SUM(early_close) AS early_close, "+
			"SUM(failed_tls + failed_auth + failed_timeout + failed_reset + failed_eof + failed_other) AS failed").
		Where("hour = ?", hour).Group("node_id, inbound, client_asn, network").Scan(&rows).Error
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
			if !seen[k] {
				obs[k] = hourRow{NodeID: k.Node, Inbound: k.Inbound, ClientASN: k.ASN, Network: k.Network}
			}
		}
		for k, r := range obs {
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
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "key"}}, DoUpdates: clause.AssignmentColumns([]string{"value"})}).
			Create(&model.State{Key: stateBaselined, Value: fmt.Sprint(hour)}).Error
	})
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
