package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"github.com/nx-panel/insight/internal/tunnels"
)

// The admin web's data: the feed's status, the matrix, the nodes and their
// overrides, the alerts, and what to move clients to.

func (s *Server) mountData(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/status", s.signedIn(s.handleStatus))
	mux.HandleFunc("GET /api/matrix", s.signedIn(s.handleMatrix))
	mux.HandleFunc("GET /api/nodes", s.signedIn(s.handleNodes))
	mux.HandleFunc("PUT /api/nodes/{id}/override", s.signedIn(s.handleOverride))
	mux.HandleFunc("GET /api/alerts", s.signedIn(s.handleAlerts))
	mux.HandleFunc("GET /api/suggestions", s.signedIn(s.handleSuggestions))
	mux.HandleFunc("GET /api/endpoints", s.signedIn(s.handleEndpoints))
	s.mountAI(mux)
}

// endpointView is one endpoint's suspicion (detect.Suspicion) with whether
// its last probed alert was followed by a path alert on it within
// detect.CalibrateWithin: what the score is calibrated against.
type endpointView struct {
	detect.Suspicion
	// Followed is null while the last probed alert is younger than the
	// calibration window and nothing followed yet, or there was none.
	Followed *bool `json:"followed"`
}

// handleEndpoints is GET /api/endpoints: every endpoint with probe
// evidence in the window or a probed episode behind it, the most suspect
// first.
func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	var rows []detect.Suspicion
	if err := s.db.WithContext(r.Context()).Order("score DESC, node_id, inbound").Limit(endpointRows).Find(&rows).Error; err != nil {
		serverError(w, err)
		return
	}
	// The newest probed alert of every endpoint and whether a path alert
	// followed it, in two queries however many endpoints there are.
	var probed []detect.Alert
	if err := s.db.WithContext(r.Context()).Where("kind = ?", detect.KindProbed).Order("id DESC").Limit(endpointAlerts).Find(&probed).Error; err != nil {
		serverError(w, err)
		return
	}
	last := map[detect.Endpoint]detect.Alert{}
	var newest []detect.Alert
	for _, a := range probed {
		e := detect.Endpoint{Node: a.NodeID, Inbound: a.Inbound}
		if _, ok := last[e]; !ok {
			last[e] = a
			newest = append(newest, a)
		}
	}
	followed, err := detect.Followed(s.db.WithContext(r.Context()), newest)
	if err != nil {
		serverError(w, err)
		return
	}
	out := make([]endpointView, 0, len(rows))
	now := time.Now().Unix()
	for _, row := range rows {
		v := endpointView{Suspicion: row}
		if a, ok := last[detect.Endpoint{Node: row.NodeID, Inbound: row.Inbound}]; ok && row.ProbedAtUnix != 0 {
			f := followed[a.ID]
			if f || now-a.At > int64(detect.CalibrateWithin/time.Second) {
				v.Followed = &f
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// endpointRows and endpointAlerts bound what the probing page reads.
const (
	endpointRows   = 500
	endpointAlerts = 2000
)

type statusView struct {
	Version     string        `json:"version"`
	Registered  bool          `json:"registered"`
	Panel       string        `json:"panel,omitempty"`
	ClaimCode   string        `json:"claimCode,omitempty"`
	Feed        ingest.Status `json:"feed"`
	ASNLoaded   bool          `json:"asnLoaded"`
	CityLoaded  bool          `json:"cityLoaded"`
	Attribution string        `json:"attribution"`
	Outages     []uint32      `json:"outages"`
	Degraded    int           `json:"degraded"`
	// Probed is how many endpoints are in a probed episode now.
	Probed int64 `json:"probed"`
	// Tunnels is the tunnel watcher's state and TunnelsDown the names of
	// the tunnels with no link now (P26).
	Tunnels     tunnels.Status `json:"tunnels"`
	TunnelsDown []string       `json:"tunnelsDown"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	v := statusView{Version: s.version, Attribution: netinfo.Attribution, Outages: []uint32{}, TunnelsDown: []string{}}
	if s.tunnels != nil {
		v.Tunnels = s.tunnels.Status()
		for _, t := range s.tunnels.Views() {
			if t.State == tunnels.Down {
				v.TunnelsDown = append(v.TunnelsDown, t.Name)
			}
		}
	} else {
		v.Tunnels.State = tunnels.StateWaiting
	}
	if c := s.addon.Credentials(); c != nil {
		v.Registered, v.Panel = true, c.Panel.URL
	} else {
		v.ClaimCode = s.addon.ClaimCode()
	}
	if s.ingest != nil {
		v.Feed = s.ingest.Status()
	}
	if s.net != nil {
		v.ASNLoaded, v.CityLoaded = s.net.Loaded()
	}
	if s.detect != nil {
		for asn := range s.detect.Outages() {
			v.Outages = append(v.Outages, asn)
		}
		sort.Slice(v.Outages, func(i, j int) bool { return v.Outages[i] < v.Outages[j] })
		v.Degraded = len(s.detect.Degraded())
	}
	if err := s.db.WithContext(r.Context()).Model(&detect.Suspicion{}).Where("probed = ?", true).Count(&v.Probed).Error; err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// windowHours reads ?hours= (1–168, default 24).
func windowHours(r *http.Request) (int, bool) {
	v := r.URL.Query().Get("hours")
	if v == "" {
		return 24, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 168 {
		return 0, false
	}
	return n, true
}

// cellView is one matrix cell: one client network on one node's inbound.
type cellView struct {
	ASN        uint32  `json:"asn"`
	Org        string  `json:"org"`
	Country    string  `json:"country"`
	Region     string  `json:"region,omitempty"`
	NodeID     uint    `json:"nodeId"`
	Inbound    string  `json:"inbound"`
	Network    string  `json:"network"`
	Accepted   uint64  `json:"accepted"`
	Authed     uint64  `json:"authed"`
	Failed     uint64  `json:"failed"`
	EarlyClose uint64  `json:"earlyClose"`
	RTTMs      float64 `json:"rttMs"`
	// RTTN is how many samples RTTMs averages, for whoever merges cells.
	RTTN       uint64  `json:"rttN"`
	RetransPPM float64 `json:"retransPpm"`
	Up         int64   `json:"up"`
	Down       int64   `json:"down"`
	Degraded   bool    `json:"degraded"`
	// Kind is "endpoint" for a WireGuard, OpenVPN or OpenConnect
	// endpoint's cell, which counts handshakes that worked and no failure
	// (ingest.KindEndpoint); empty for an inbound, or when the panel did
	// not say.
	Kind string `json:"kind,omitempty"`
}

type matrixRow struct {
	ClientASN  uint32
	Country    string
	Region     string
	NodeID     uint
	Inbound    string
	Network    string
	Accepted   uint64
	Authed     uint64
	Failed     uint64
	EarlyClose uint64
	RTTSum     uint64 `gorm:"column:rtt_sum"`
	RTTN       uint64 `gorm:"column:rtt_n"`
	RetransSum uint64 `gorm:"column:retrans_sum"`
	RetransN   uint64 `gorm:"column:retrans_n"`
	Up         int64
	Down       int64
}

// matrixCells bounds the answer to the busiest cells: the page shows the top
// networks, and a week by region on a large fleet is otherwise tens of
// megabytes every refresh.
const (
	matrixCells    = 5000
	matrixDegraded = 300
)

// handleMatrix is GET /api/matrix?hours=&by=asn|region: the last hours of
// every client network × node × inbound, from the hourly cells.
func (s *Server) handleMatrix(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	hours, ok := windowHours(r)
	if !ok {
		writeCode(w, http.StatusBadRequest, "bad_hours", "hours must be 1–168")
		return
	}
	byRegion := r.URL.Query().Get("by") == "region"
	group := "client_asn, country, node_id, inbound, network"
	if byRegion {
		group = "client_asn, country, region, node_id, inbound, network"
	}
	sel := group + ", SUM(accepted) AS accepted, SUM(authed) AS authed, " +
		"SUM(failed_tls + failed_auth + failed_timeout + failed_reset + failed_eof + failed_other) AS failed, " +
		"SUM(early_close) AS early_close, SUM(rtt_sum) AS rtt_sum, SUM(rtt_n) AS rtt_n, " +
		"SUM(retrans_sum) AS retrans_sum, SUM(retrans_n) AS retrans_n, SUM(up) AS up, SUM(down) AS down"
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Truncate(time.Hour).Unix()
	var rows []matrixRow
	if err := s.db.WithContext(r.Context()).Model(&model.PathHour{}).Select(sel).Where("hour >= ?", since).Group(group).
		Order("SUM(accepted) DESC").Limit(matrixCells).Scan(&rows).Error; err != nil {
		serverError(w, err)
		return
	}
	degraded := map[detect.Key]bool{}
	if s.detect != nil {
		degraded = s.detect.Degraded()
	}
	// The cap keeps the busiest cells, and a path that is down is the
	// quietest there is: the degraded ones the cap cut are read by key and
	// put back, a bounded number of them.
	if len(rows) == matrixCells && len(degraded) > 0 {
		have := map[detect.Key]bool{}
		for _, row := range rows {
			have[detect.Key{Node: row.NodeID, Inbound: row.Inbound, ASN: row.ClientASN, Network: row.Network}] = true
		}
		q := s.db.WithContext(r.Context()).Model(&model.PathHour{}).Select(sel).Where("hour >= ?", since)
		var or *gorm.DB
		missing := 0
		for k := range degraded {
			if have[k] || missing == matrixDegraded {
				continue
			}
			cond := s.db.Where("node_id = ? AND inbound = ? AND client_asn = ? AND network = ?", k.Node, k.Inbound, k.ASN, k.Network)
			if missing == 0 {
				or = cond
			} else {
				or = or.Or(cond)
			}
			missing++
		}
		if missing > 0 {
			var more []matrixRow
			if err := q.Where(or).Group(group).Scan(&more).Error; err != nil {
				serverError(w, err)
				return
			}
			rows = append(rows, more...)
		}
	}
	var shapes map[uint]map[string]ingest.Shape
	if s.ingest != nil {
		shapes = s.ingest.Shapes()
	}
	cells := make([]cellView, 0, len(rows))
	for _, r := range rows {
		c := cellView{
			ASN: r.ClientASN, Country: r.Country, Region: r.Region, NodeID: r.NodeID, Inbound: r.Inbound, Network: r.Network,
			Accepted: r.Accepted, Authed: r.Authed, Failed: r.Failed, EarlyClose: r.EarlyClose, Up: r.Up, Down: r.Down,
			Degraded: degraded[detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}],
		}
		if sh, ok := shapes[r.NodeID][r.Inbound]; ok && sh.Kind == ingest.KindEndpoint {
			c.Kind = ingest.KindEndpoint
		}
		if s.net != nil {
			c.Org = s.net.Org(r.ClientASN)
		}
		if r.RTTN > 0 {
			c.RTTMs, c.RTTN = float64(r.RTTSum)/float64(r.RTTN), r.RTTN
		}
		if r.RetransN > 0 {
			c.RetransPPM = float64(r.RetransSum) / float64(r.RetransN)
		}
		cells = append(cells, c)
	}
	var nodes []model.NodeNetinfo
	if err := s.db.WithContext(r.Context()).Order("node_id").Find(&nodes).Error; err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hours": hours, "cells": cells, "nodes": nodeViews(nodes)})
}

type nodeView struct {
	model.NodeNetinfo
	Effective struct {
		ASN     uint32 `json:"asn"`
		Org     string `json:"org"`
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"effective"`
}

func nodeViews(nodes []model.NodeNetinfo) []nodeView {
	out := make([]nodeView, 0, len(nodes))
	for _, n := range nodes {
		v := nodeView{NodeNetinfo: n}
		v.Effective.ASN, v.Effective.Org, v.Effective.Country, v.Effective.City = n.Effective()
		out = append(out, v)
	}
	return out
}

// nodeRow is a node on the Nodes page: its network, what it serves, and
// the tunnels it is a relay or an origin of.
type nodeRow struct {
	nodeView
	Inbounds []ingest.Shape `json:"inbounds"`
	Tunnels  []tunnelOnNode `json:"tunnels"`
}

// tunnelOnNode is a tunnel seen from one of its nodes.
type tunnelOnNode struct {
	tunnels.View
	Role string `json:"role"` // relay | origin
	// Hours are its links' counts on this node over the last 24 hours.
	Hours tunnelTotals `json:"hours"`
}

// tunnelTotals are a tunnel's link counts on one node over a window.
type tunnelTotals struct {
	Attempts uint64 `json:"attempts"`
	Up       uint64 `json:"up"`
	Failed   uint64 `json:"failed"`
	Flapped  uint64 `json:"flapped"`
}

// tunnelWindow is what the Nodes page sums a tunnel's links over.
const tunnelWindow = 24 * time.Hour

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	var nodes []model.NodeNetinfo
	if err := s.db.WithContext(r.Context()).Order("node_id").Find(&nodes).Error; err != nil {
		serverError(w, err)
		return
	}
	totals, err := s.tunnelTotals(r, time.Now().Add(-tunnelWindow))
	if err != nil {
		serverError(w, err)
		return
	}
	var views []tunnels.View
	if s.tunnels != nil {
		views = s.tunnels.Views()
	}
	var shapes map[uint]map[string]ingest.Shape
	if s.ingest != nil {
		shapes = s.ingest.Shapes()
	}
	out := make([]nodeRow, 0, len(nodes))
	for _, v := range nodeViews(nodes) {
		row := nodeRow{nodeView: v, Inbounds: []ingest.Shape{}, Tunnels: []tunnelOnNode{}}
		for _, sh := range shapes[v.NodeID] {
			row.Inbounds = append(row.Inbounds, sh)
		}
		sort.Slice(row.Inbounds, func(i, j int) bool { return row.Inbounds[i].Tag < row.Inbounds[j].Tag })
		for _, t := range views {
			role := ""
			if t.RelayID == v.NodeID {
				role = "relay"
			} else {
				for _, o := range t.OriginIDs {
					if o == v.NodeID {
						role = "origin"
					}
				}
			}
			if role == "" {
				continue
			}
			row.Tunnels = append(row.Tunnels, tunnelOnNode{View: t, Role: role, Hours: totals[tunnelNode{v.NodeID, t.Name}]})
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

type tunnelNode struct {
	node uint
	name string
}

// tunnelTotals sums every node's tunnel hours since a time, by node and
// tunnel name. A link's samples carry the tunnel's tag on the node, which
// the panel derives from the name; both are matched.
func (s *Server) tunnelTotals(r *http.Request, since time.Time) (map[tunnelNode]tunnelTotals, error) {
	var rows []struct {
		NodeID   uint
		Tunnel   string
		Attempts uint64
		Up       uint64
		Failed   uint64
		Flapped  uint64
	}
	err := s.db.WithContext(r.Context()).Model(&model.TunnelHour{}).
		Select("node_id, tunnel, SUM(attempts) AS attempts, SUM(up) AS up, SUM(flapped) AS flapped, "+
			"SUM(failed_dial + failed_tls + failed_preface + failed_refused + failed_timeout + failed_reset + failed_eof + failed_other) AS failed").
		Where("hour >= ?", since.Truncate(time.Hour).Unix()).Group("node_id, tunnel").Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	var views []tunnels.View
	if s.tunnels != nil {
		views = s.tunnels.Views()
	}
	byTag := map[string]string{}
	for _, v := range views {
		byTag[v.Tag] = v.Name
	}
	out := map[tunnelNode]tunnelTotals{}
	for _, row := range rows {
		name := row.Tunnel
		if n, ok := byTag[row.Tunnel]; ok {
			name = n
		}
		k := tunnelNode{row.NodeID, name}
		t := out[k]
		t.Attempts += row.Attempts
		t.Up += row.Up
		t.Failed += row.Failed
		t.Flapped += row.Flapped
		out[k] = t
	}
	return out, nil
}

// handleOverride is PUT /api/nodes/{id}/override: what the admin says the
// node's network is; empty fields put the database's answer back.
func (s *Server) handleOverride(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 32)
	if err != nil {
		writeCode(w, http.StatusBadRequest, "bad_request", "invalid node id")
		return
	}
	var req struct {
		ASN     uint32 `json:"asn"`
		Org     string `json:"org"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if err := decode(r, &req); err != nil {
		badBody(w)
		return
	}
	switch err := ingest.Override(s.db.WithContext(r.Context()), uint(id), req.ASN, req.Org, req.Country, req.City); {
	case errors.Is(err, gorm.ErrRecordNotFound):
		writeCode(w, http.StatusNotFound, "not_found", "no such node")
	case errors.Is(err, ingest.ErrCountry):
		writeCode(w, http.StatusBadRequest, "bad_country", err.Error())
	case errors.Is(err, ingest.ErrOverride):
		writeCode(w, http.StatusBadRequest, "bad_override", err.Error(), "max", strconv.Itoa(ingest.OverrideMax))
	case err != nil:
		serverError(w, err)
	default:
		var n model.NodeNetinfo
		if err := s.db.WithContext(r.Context()).First(&n, id).Error; err != nil {
			serverError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, nodeViews([]model.NodeNetinfo{n})[0])
	}
}

// handleAlerts is GET /api/alerts?limit=&before=: newest first.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeCode(w, http.StatusBadRequest, "bad_request", "limit must be 1–1000")
			return
		}
		limit = n
	}
	q := s.db.WithContext(r.Context()).Order("id DESC").Limit(limit)
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeCode(w, http.StatusBadRequest, "bad_request", "before must be an alert id")
			return
		}
		q = q.Where("id < ?", n)
	}
	alerts := []detect.Alert{}
	if err := q.Find(&alerts).Error; err != nil {
		serverError(w, err)
		return
	}
	type alertView struct {
		detect.Alert
		Org string `json:"org"`
	}
	out := make([]alertView, 0, len(alerts))
	for _, a := range alerts {
		v := alertView{Alert: a}
		if s.net != nil {
			v.Org = s.net.Org(a.ASN)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

// suggestion is where a degraded path's clients have somewhere to go: the
// same client network's paths that work over the last six hours.
type suggestion struct {
	ASN          uint32        `json:"asn"`
	Org          string        `json:"org"`
	NodeID       uint          `json:"nodeId"`
	Inbound      string        `json:"inbound"`
	Network      string        `json:"network"`
	Alternatives []alternative `json:"alternatives"`
}

type alternative struct {
	NodeID  uint    `json:"nodeId"`
	Inbound string  `json:"inbound"`
	Network string  `json:"network"`
	Success float64 `json:"success"`
}

const (
	suggestWindow  = 6 * time.Hour
	suggestMin     = 10
	suggestSuccess = 0.8
)

// handleSuggestions is GET /api/suggestions: for every degraded path not
// inside an ASN outage (P20: nothing to rotate there) nor on the relay of a
// tunnel that is down (P26: the tunnel is the cause), the paths that work
// for that client network instead. The subscription hints already put them
// first; this is what the admin can do about the rest — move the users,
// change the node's address or the inbound's port or SNI.
func (s *Server) handleSuggestions(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	out := []suggestion{}
	if s.detect == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	outages := s.detect.Outages()
	degraded := s.detect.Degraded()
	tunnelDown := map[uint]bool{}
	if s.tunnels != nil {
		tunnelDown = s.tunnels.Down()
	}
	if len(degraded) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	since := time.Now().Add(-suggestWindow).Truncate(time.Hour).Unix()
	var rows []matrixRow
	if err := s.db.WithContext(r.Context()).Model(&model.PathHour{}).
		Select("client_asn, node_id, inbound, network, SUM(accepted) AS accepted, SUM(authed) AS authed").
		Where("hour >= ? AND client_asn <> ?", since, model.OtherASN).Group("client_asn, node_id, inbound, network").Scan(&rows).Error; err != nil {
		serverError(w, err)
		return
	}
	byASN := map[uint32][]alternative{}
	for _, r := range rows {
		if r.Accepted < suggestMin {
			continue
		}
		k := detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}
		success := float64(r.Authed) / float64(r.Accepted)
		if degraded[k] || success < suggestSuccess {
			continue
		}
		byASN[r.ClientASN] = append(byASN[r.ClientASN], alternative{NodeID: r.NodeID, Inbound: r.Inbound, Network: r.Network, Success: success})
	}
	for k := range degraded {
		if outages[k.ASN] || tunnelDown[k.Node] {
			continue // nothing to rotate: the network, or the tunnel behind the node
		}
		alts := byASN[k.ASN]
		sort.Slice(alts, func(i, j int) bool { return alts[i].Success > alts[j].Success })
		sg := suggestion{ASN: k.ASN, NodeID: k.Node, Inbound: k.Inbound, Network: k.Network, Alternatives: append([]alternative{}, alts...)}
		if s.net != nil {
			sg.Org = s.net.Org(k.ASN)
		}
		out = append(out, sg)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ASN != out[j].ASN {
			return out[i].ASN < out[j].ASN
		}
		return out[i].NodeID < out[j].NodeID
	})
	writeJSON(w, http.StatusOK, out)
}
