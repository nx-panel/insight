package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"

	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/model"
)

// Mode A in the admin web: the model's settings, the reports, a pass now.

func (s *Server) mountAI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ai", s.signedIn(s.handleAIGet))
	mux.HandleFunc("PUT /api/ai", s.signedIn(s.handleAIPut))
	mux.HandleFunc("GET /api/ai/reports", s.signedIn(s.handleAIReports))
	mux.HandleFunc("POST /api/ai/run", s.signedIn(s.handleAIRun))
}

// aiView is the settings as the web sees them: the key only as whether
// one is set.
type aiView struct {
	Enabled     bool     `json:"enabled"`
	URL         string   `json:"url"`
	Model       string   `json:"model"`
	Proxy       string   `json:"proxy"`
	DailyTokens int      `json:"dailyTokens"`
	KeySet      bool     `json:"keySet"`
	UsedToday   int      `json:"usedToday"`
	Running     bool     `json:"running"`
	Countries   []string `json:"countries"`
}

func (s *Server) aiView(r *http.Request) (aiView, error) {
	st, err := ai.Load(r.Context(), s.db)
	if err != nil {
		return aiView{}, err
	}
	v := aiView{
		Enabled: st.Enabled, URL: st.URL, Model: st.Model, Proxy: ai.MaskProxy(st.Proxy), DailyTokens: st.DailyTokens,
		KeySet: st.Key != "", Countries: append([]string{}, s.countries...),
	}
	if s.ai != nil {
		v.Running = s.ai.Running()
		if v.UsedToday, err = s.ai.UsedToday(r.Context()); err != nil {
			return v, err
		}
	}
	return v, nil
}

func (s *Server) handleAIGet(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	v, err := s.aiView(r)
	if err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleAIPut is PUT /api/ai. An empty key keeps the one saved — for the
// same API scheme, host and port and the same proxy only; a change of any
// of them without the key drops it (ai.Settings.SameProvider). clearKey removes it (a local model needs
// none).
func (s *Server) handleAIPut(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	var body struct {
		Enabled     bool   `json:"enabled"`
		URL         string `json:"url"`
		Model       string `json:"model"`
		Key         string `json:"key"`
		ClearKey    bool   `json:"clearKey"`
		Proxy       string `json:"proxy"`
		DailyTokens int    `json:"dailyTokens"`
	}
	if decode(r, &body) != nil {
		badBody(w)
		return
	}
	old, err := ai.Load(r.Context(), s.db)
	if err != nil {
		serverError(w, err)
		return
	}
	st := ai.Settings{Enabled: body.Enabled, URL: body.URL, Model: body.Model, Proxy: ai.UnmaskProxy(body.Proxy, old.Proxy), DailyTokens: body.DailyTokens, Key: old.Key}
	switch {
	case body.Key != "":
		st.Key = body.Key
	case body.ClearKey || !st.SameProvider(old):
		st.Key = ""
	}
	if err := ai.Save(r.Context(), s.db, st); err != nil {
		for _, c := range []struct {
			err  error
			code string
		}{{ai.ErrBudget, "ai_budget"}, {ai.ErrURL, "ai_url"}, {ai.ErrProxy, "ai_proxy"}, {ai.ErrNeeds, "ai_needs"}} {
			if errors.Is(err, c.err) {
				var params []string
				if errors.Is(c.err, ai.ErrBudget) {
					params = []string{"min", strconv.Itoa(ai.MinDailyTokens), "max", strconv.Itoa(ai.MaxDailyTokens)}
				}
				writeCode(w, http.StatusBadRequest, c.code, err.Error(), params...)
				return
			}
		}
		serverError(w, err)
		return
	}
	s.handleAIGet(w, r, model.Admin{})
}

// reportsPerCountry is how many of a country's reports the page is given.
const reportsPerCountry = 20

// handleAIReports is GET /api/ai/reports: each analysed country's newest
// reports, or one country's when ?country= names it, with the names of the networks
// their findings mention (the reports keep numbers only).
func (s *Server) handleAIReports(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	// Each country's own newest, not the newest overall: one country with
	// an alert an hour would push another's last report off the page.
	countries := s.countries
	if c := r.URL.Query().Get("country"); c != "" {
		countries = []string{c}
	}
	out := []ai.Report{}
	for _, c := range countries {
		var got []ai.Report
		if err := s.db.WithContext(r.Context()).Where("country = ?", c).Order("id DESC").Limit(reportsPerCountry).Find(&got).Error; err != nil {
			serverError(w, err)
			return
		}
		out = append(out, got...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	orgs := map[string]string{}
	for _, rep := range out {
		var found []ai.Finding
		if json.Unmarshal([]byte(rep.Findings), &found) != nil {
			continue
		}
		for _, f := range found {
			if f.ASN != 0 && s.net != nil {
				orgs[strconv.FormatUint(uint64(f.ASN), 10)] = s.net.Org(f.ASN)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "orgs": orgs})
}

// handleAIRun is POST /api/ai/run {country}: a pass now, in the
// background; 409 while one runs.
func (s *Server) handleAIRun(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	var body struct {
		Country string `json:"country"`
	}
	if decode(r, &body) != nil || !slices.Contains(s.countries, body.Country) {
		badBody(w)
		return
	}
	st, err := ai.Load(r.Context(), s.db)
	if err != nil {
		serverError(w, err)
		return
	}
	if !st.Enabled || s.ai == nil {
		writeCode(w, http.StatusConflict, "ai_off", "the AI analysis is off")
		return
	}
	// The pass outlives the request.
	if !s.ai.RunNow(context.WithoutCancel(r.Context()), body.Country) {
		writeCode(w, http.StatusConflict, "ai_running", "a pass is already running")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"started": true})
}
