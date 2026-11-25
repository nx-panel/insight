package web

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/model"
)

// Mode B in the admin web (internal/cloud): the switch, what was sent,
// NX's report.

func (s *Server) mountCloud(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/cloud", s.signedIn(s.handleCloudGet))
	mux.HandleFunc("PUT /api/cloud", s.signedIn(s.handleCloudPut))
	mux.HandleFunc("GET /api/cloud/batches/{hour}", s.signedIn(s.handleCloudBatch))
	mux.HandleFunc("POST /api/cloud/report", s.signedIn(s.handleCloudReport))
}

type cloudView struct {
	cloud.Status
	Report cloud.Held `json:"report"`
}

func (s *Server) cloudView(r *http.Request) (cloudView, error) {
	st, err := s.cloud.Status(r.Context())
	if err != nil {
		return cloudView{}, err
	}
	return cloudView{Status: st, Report: s.cloud.Held(r.Context())}, nil
}

// handleCloudGet is GET /api/cloud. Opening the page is also the moment
// Insight asks NX for a newer report: in the background, at most once every
// cloud.ReportGap.
func (s *Server) handleCloudGet(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.cloud == nil {
		writeCode(w, http.StatusNotFound, "not_found", "Mode B is not available")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Minute)
		defer cancel()
		_ = s.cloud.CheckReport(ctx, false)
	}()
	v, err := s.cloudView(r)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleCloudPut is PUT /api/cloud {on}. A panel that cannot be reached
// leaves Mode B on with the key waiting to be registered; the answer says
// so in error.
func (s *Server) handleCloudPut(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.cloud == nil {
		writeCode(w, http.StatusNotFound, "not_found", "Mode B is not available")
		return
	}
	var body struct {
		On bool `json:"on"`
	}
	if decode(r, &body) != nil {
		badBody(w)
		return
	}
	err := s.cloud.SetOn(r.Context(), body.On)
	v, verr := s.cloudView(r)
	if verr != nil {
		serverError(w, verr)
		return
	}
	if err != nil {
		v.Error = err.Error()
	}
	writeJSON(w, http.StatusOK, v)
}

// handleCloudBatch is one hour's batch as it went (or goes) out.
func (s *Server) handleCloudBatch(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.cloud == nil {
		writeCode(w, http.StatusNotFound, "not_found", "Mode B is not available")
		return
	}
	hour, err := strconv.ParseInt(r.PathValue("hour"), 10, 64)
	if err != nil {
		badBody(w)
		return
	}
	b, err := s.cloud.Sent(r.Context(), hour)
	if err != nil {
		writeCode(w, http.StatusNotFound, "not_found", "no batch of that hour")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// handleCloudReport asks NX now; once a minute at most.
func (s *Server) handleCloudReport(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.cloud == nil {
		writeCode(w, http.StatusNotFound, "not_found", "Mode B is not available")
		return
	}
	if !s.forced.allow(time.Minute) {
		writeCode(w, http.StatusTooManyRequests, "too_soon", "asked less than a minute ago")
		return
	}
	_ = s.cloud.CheckReport(r.Context(), true)
	v, err := s.cloudView(r)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
