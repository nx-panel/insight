// Package tunnels watches the operator's node-to-node tunnels. A user's path ends at the relay node,
// where they connect; behind it a tunnel carries their traffic to an origin
// node. A censor that cuts that link shows on the relay as every client
// network failing at once — read as the relay's inbounds blocked, with a
// rotation suggested for something that is not blocked. So each tunnel's
// live status is asked every minute (GET /api/v1/tunnels/{id}/status,
// tunnels:read), and a tunnel with no link is the cause of its relay's drop:
// one tunnel.down alert, no path alert for the relay, nothing to rotate.
//
// A state moves after two polls in a row agree, like a path's. A relay the
// panel cannot reach says nothing about its tunnel: its node is down, which
// the paths already show.
package tunnels

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/detect"
)

const (
	// PollEvery is how often every tunnel's status is asked.
	PollEvery = time.Minute
	// confirm is how many polls in a row move a state.
	confirm = 2
	// statusTimeout bounds one status call: the panel asks both halves
	// with fifteen seconds each.
	statusTimeout = 20 * time.Second
	// maxTunnels bounds what one poll asks about, and statusAtOnce how many
	// status calls are in flight: each one has the panel ask two nodes.
	maxTunnels   = 200
	statusAtOnce = 8
)

// Poll states, for the admin web.
const (
	StateWaiting     = "waiting"     // not registered with a panel yet
	StateOK          = "ok"          // polling
	StateUnsupported = "unsupported" // the panel predates the route
	StateNoScope     = "no-scope"    // the token lacks tunnels:read
	StateError       = "error"       // the last poll failed otherwise
)

// Getter is the panel client's one call this package makes.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// TunnelState is one tunnel that is down, kept so a restart neither alerts
// again nor forgets to say it came back.
type TunnelState struct {
	TunnelID uint   `gorm:"primaryKey;autoIncrement:false"`
	Name     string `gorm:"not null;size:128"`
	RelayID  uint   `gorm:"not null"`
	Since    int64  `gorm:"not null"`
}

func (TunnelState) TableName() string { return "tunnel_states" }

// Tables are this package's, for the migration.
func Tables() []any { return []any{&TunnelState{}} }

// tunnel is a row of GET /api/v1/tunnels, what this package reads of it.
type tunnel struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	Tag         string   `json:"tag"`
	Mode        string   `json:"mode"`
	Enabled     *bool    `json:"enabled"`
	RelayNodeID uint     `json:"relayNodeId"`
	RelayName   string   `json:"relayName"`
	OriginIDs   []uint   `json:"originIds"`
	OriginNames []string `json:"originNames"`
}

type listPage struct {
	Items []tunnel `json:"items"`
}

// status is GET /api/v1/tunnels/{id}/status.
type status struct {
	Healthy bool         `json:"healthy"`
	Relay   halfStatus   `json:"relay"`
	Origins []halfStatus `json:"origins"`
}

type halfStatus struct {
	NodeID    uint   `json:"nodeId"`
	NodeName  string `json:"nodeName"`
	Reachable bool   `json:"reachable"`
	Error     string `json:"error"`
	Sessions  []struct {
		OriginID uint `json:"originId"`
		Streams  int  `json:"streams"`
	} `json:"sessions"`
}

// View is one tunnel as the admin web and the AI table show it.
type View struct {
	ID          uint     `json:"id"`
	Name        string   `json:"name"`
	Tag         string   `json:"tag"`
	Mode        string   `json:"mode"`
	Enabled     bool     `json:"enabled"`
	RelayID     uint     `json:"relayId"`
	RelayName   string   `json:"relayName"`
	OriginIDs   []uint   `json:"originIds"`
	OriginNames []string `json:"originNames"`
	// State is up, down, or unknown (not asked yet, disabled, or the relay
	// not reachable).
	State string `json:"state"`
	// Since is when a down tunnel went down.
	Since int64 `json:"since,omitempty"`
	// Unlinked are the origins with no link at the relay at the last poll:
	// a tunnel with several origins can be up while one of them is cut.
	Unlinked  []uint `json:"unlinked,omitempty"`
	CheckedAt int64  `json:"checkedAt,omitempty"`
}

// View states.
const (
	Up      = "up"
	Down    = "down"
	Unknown = "unknown"
)

// Status is the watcher's own state, for the admin web.
type Status struct {
	State    string    `json:"state"`
	Error    string    `json:"error,omitempty"`
	LastPoll time.Time `json:"lastPoll"`
}

type judged struct {
	down      bool // the confirmed state
	bad, good int
	since     int64
	view      View
}

// Watcher polls the tunnels and keeps their states.
type Watcher struct {
	DB *gorm.DB
	// Panel is the client to poll, nil while unregistered.
	Panel func() Getter
	// Send delivers an alert; nil stores only.
	Send func(context.Context, detect.Alert)
	Now  func() time.Time

	mu     sync.Mutex
	loaded bool
	states map[uint]*judged
	status Status
}

func (w *Watcher) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run polls for the life of ctx.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(PollEvery)
	defer t.Stop()
	for {
		if err := w.Poll(ctx); err != nil {
			log.Printf("tunnels: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Down is the relays of the tunnels that are down: what the detector holds
// path alerts back for.
func (w *Watcher) Down() map[uint]bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[uint]bool{}
	for _, st := range w.states {
		if st.down {
			out[st.view.RelayID] = true
		}
	}
	return out
}

// Views is every tunnel as last polled, by id.
func (w *Watcher) Views() []View {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]View, 0, len(w.states))
	for _, st := range w.states {
		v := st.view
		v.OriginIDs = append([]uint(nil), v.OriginIDs...)
		v.OriginNames = append([]string(nil), v.OriginNames...)
		v.Unlinked = append([]uint(nil), v.Unlinked...)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Status is a copy of the watcher's state.
func (w *Watcher) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.status
	if s.State == "" {
		s.State = StateWaiting
	}
	return s
}

func (w *Watcher) load(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.loaded {
		return nil
	}
	var rows []TunnelState
	if err := w.DB.WithContext(ctx).Find(&rows).Error; err != nil {
		return err
	}
	w.states = map[uint]*judged{}
	for _, r := range rows {
		w.states[r.TunnelID] = &judged{down: true, since: r.Since, view: View{
			ID: r.TunnelID, Name: r.Name, RelayID: r.RelayID, Enabled: true, State: Down, Since: r.Since,
		}}
	}
	w.loaded = true
	return nil
}

func (w *Watcher) setError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.LastPoll = w.now()
	w.status.Error = err.Error()
	switch {
	case panel.IsStatus(err, http.StatusNotFound):
		w.status.State = StateUnsupported
	case panel.IsStatus(err, http.StatusForbidden):
		w.status.State = StateNoScope
	default:
		w.status.State = StateError
	}
}

// Poll asks for every tunnel and each one's status, and moves the states.
func (w *Watcher) Poll(ctx context.Context) error {
	if w.Panel == nil {
		return nil
	}
	client := w.Panel()
	if client == nil {
		return nil
	}
	if err := w.load(ctx); err != nil {
		return err
	}
	var list listPage
	if err := client.Get(ctx, "/tunnels?limit="+strconv.Itoa(maxTunnels), &list); err != nil {
		w.setError(err)
		return err
	}
	type asked struct {
		t   tunnel
		st  *status
		err error
	}
	results := make([]asked, len(list.Items))
	var wg sync.WaitGroup
	slots := make(chan struct{}, statusAtOnce)
	for i, t := range list.Items {
		results[i].t = t
		if t.Enabled != nil && !*t.Enabled {
			continue
		}
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			cctx, cancel := context.WithTimeout(ctx, statusTimeout)
			defer cancel()
			var st status
			if err := client.Get(cctx, "/tunnels/"+strconv.FormatUint(uint64(t.ID), 10)+"/status", &st); err != nil {
				results[i].err = err
				return
			}
			results[i].st = &st
		})
	}
	wg.Wait()

	now := w.now()
	at := now.Unix()
	var alerts []detect.Alert
	var put []TunnelState
	var drop []uint
	w.mu.Lock()
	w.status = Status{State: StateOK, LastPoll: now}
	seen := map[uint]bool{}
	for _, r := range results {
		t := r.t
		seen[t.ID] = true
		st := w.states[t.ID]
		if st == nil {
			st = &judged{}
			w.states[t.ID] = st
		}
		st.view = View{
			ID: t.ID, Name: t.Name, Tag: t.Tag, Mode: t.Mode, Enabled: t.Enabled == nil || *t.Enabled,
			RelayID: t.RelayNodeID, RelayName: t.RelayName, OriginIDs: t.OriginIDs, OriginNames: t.OriginNames,
			State: Unknown, CheckedAt: at,
		}
		switch {
		case !st.view.Enabled:
			// Switched off by the operator: not a tunnel that broke.
			if st.down {
				drop = append(drop, t.ID)
			}
			st.down, st.bad, st.good = false, 0, 0
			continue
		case r.err != nil || r.st == nil || !r.st.Relay.Reachable:
			// Not asked, or the relay is down itself: nothing about the
			// tunnel. The state stays.
			if st.down {
				st.view.State, st.view.Since = Down, st.since
			}
			continue
		}
		st.view.Unlinked = unlinked(t.OriginIDs, r.st.Relay)
		if !r.st.Healthy {
			st.bad, st.good = st.bad+1, 0
			if !st.down && st.bad >= confirm {
				st.down, st.since = true, at
				put = append(put, TunnelState{TunnelID: t.ID, Name: t.Name, RelayID: t.RelayNodeID, Since: at})
				alerts = append(alerts, tunnelAlert(detect.KindTunnelDown, t, r.st, at))
			}
		} else {
			st.good, st.bad = st.good+1, 0
			if st.down && st.good >= confirm {
				st.down = false
				drop = append(drop, t.ID)
				alerts = append(alerts, tunnelAlert(detect.KindTunnelUp, t, r.st, at))
			}
		}
		st.view.State = Up
		if st.down {
			st.view.State, st.view.Since = Down, st.since
		}
	}
	// A tunnel deleted on the panel is forgotten without a word.
	for id, st := range w.states {
		if !seen[id] {
			if st.down {
				drop = append(drop, id)
			}
			delete(w.states, id)
		}
	}
	w.mu.Unlock()
	if len(put) == 0 && len(drop) == 0 && len(alerts) == 0 {
		return nil
	}
	err := w.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(drop) > 0 {
			if err := tx.Where("tunnel_id IN ?", drop).Delete(&TunnelState{}).Error; err != nil {
				return err
			}
		}
		if len(put) > 0 {
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).Create(&put).Error; err != nil {
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
	if err != nil {
		w.mu.Lock()
		w.loaded = false // back to what the database holds
		w.mu.Unlock()
		return err
	}
	if w.Send != nil {
		for i := range alerts {
			w.Send(ctx, alerts[i])
		}
	}
	return nil
}

// unlinked is the origins the relay holds no session from. Sessions name
// their origin when the panel knows it; a relay listing sessions without
// origins tells nothing.
func unlinked(origins []uint, relay halfStatus) []uint {
	linked := map[uint]bool{}
	named := false
	for _, s := range relay.Sessions {
		if s.OriginID != 0 {
			linked[s.OriginID] = true
			named = true
		}
	}
	if !named && len(relay.Sessions) > 0 {
		return nil
	}
	var out []uint
	for _, id := range origins {
		if !linked[id] {
			out = append(out, id)
		}
	}
	return out
}

// Detail is a tunnel alert's Detail: the tunnel, and which of its origins
// the panel could not reach — an origin that is down rather than a link
// that is cut.
type Detail struct {
	TunnelID    uint     `json:"tunnelId"`
	Origins     []string `json:"origins"`
	Unreachable []string `json:"unreachable,omitempty"`
}

func tunnelAlert(kind string, t tunnel, st *status, at int64) detect.Alert {
	d := Detail{TunnelID: t.ID, Origins: t.OriginNames}
	for _, o := range st.Origins {
		if !o.Reachable {
			d.Unreachable = append(d.Unreachable, o.NodeName)
		}
	}
	raw, _ := json.Marshal(d)
	return detect.Alert{Kind: kind, NodeID: t.RelayNodeID, Tunnel: t.Name, At: at, Detail: string(raw)}
}
