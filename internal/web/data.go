package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"gorm.io/gorm"
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
}

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
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request, _ model.Admin) {
	v := statusView{Version: s.version, Attribution: netinfo.Attribution, Outages: []uint32{}}
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
	RetransPPM float64 `json:"retransPpm"`
	Up         int64   `json:"up"`
	Down       int64   `json:"down"`
	Degraded   bool    `json:"degraded"`
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
	if err := s.db.Model(&model.PathHour{}).Select(sel).Where("hour >= ?", since).Group(group).Scan(&rows).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	degraded := map[detect.Key]bool{}
	if s.detect != nil {
		degraded = s.detect.Degraded()
	}
	cells := make([]cellView, 0, len(rows))
	for _, r := range rows {
		c := cellView{
			ASN: r.ClientASN, Country: r.Country, Region: r.Region, NodeID: r.NodeID, Inbound: r.Inbound, Network: r.Network,
			Accepted: r.Accepted, Authed: r.Authed, Failed: r.Failed, EarlyClose: r.EarlyClose, Up: r.Up, Down: r.Down,
			Degraded: degraded[detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ClientASN, Network: r.Network}],
		}
		if s.net != nil {
			c.Org = s.net.Org(r.ClientASN)
		}
		if r.RTTN > 0 {
			c.RTTMs = float64(r.RTTSum) / float64(r.RTTN)
		}
		if r.RetransN > 0 {
			c.RetransPPM = float64(r.RetransSum) / float64(r.RetransN)
		}
		cells = append(cells, c)
	}
	var nodes []model.NodeNetinfo
	if err := s.db.Order("node_id").Find(&nodes).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
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

func (s *Server) handleNodes(w http.ResponseWriter, _ *http.Request, _ model.Admin) {
	var nodes []model.NodeNetinfo
	if err := s.db.Order("node_id").Find(&nodes).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nodeViews(nodes))
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
	switch err := ingest.Override(s.db, uint(id), req.ASN, req.Org, req.Country, req.City); {
	case errors.Is(err, gorm.ErrRecordNotFound):
		writeCode(w, http.StatusNotFound, "not_found", "no such node")
	case err != nil && strings.Contains(err.Error(), "country"):
		writeCode(w, http.StatusBadRequest, "bad_country", err.Error())
	case err != nil:
		writeErr(w, http.StatusInternalServerError, err.Error())
	default:
		var n model.NodeNetinfo
		s.db.First(&n, id)
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
	q := s.db.Order("id DESC").Limit(limit)
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
		writeErr(w, http.StatusInternalServerError, err.Error())
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
// inside an ASN outage (P20: nothing to rotate there), the paths that work
// for that client network instead. The subscription hints already put them
// first; this is what the admin can do about the rest — move the users,
// change the node's address or the inbound's port or SNI.
func (s *Server) handleSuggestions(w http.ResponseWriter, _ *http.Request, _ model.Admin) {
	out := []suggestion{}
	if s.detect == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	outages := s.detect.Outages()
	degraded := s.detect.Degraded()
	if len(degraded) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}
	since := time.Now().Add(-suggestWindow).Truncate(time.Hour).Unix()
	var rows []matrixRow
	if err := s.db.Model(&model.PathHour{}).
		Select("client_asn, node_id, inbound, network, SUM(accepted) AS accepted, SUM(authed) AS authed").
		Where("hour >= ? AND client_asn <> 0", since).Group("client_asn, node_id, inbound, network").Scan(&rows).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
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
		if outages[k.ASN] {
			continue
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
