package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
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
		Enabled: st.Enabled, URL: st.URL, Model: st.Model, Proxy: st.Proxy, DailyTokens: st.DailyTokens,
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
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// handleAIPut is PUT /api/ai. An empty key keeps the one saved; clearKey
// removes it (a local model needs none).
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
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := ai.Settings{Enabled: body.Enabled, URL: body.URL, Model: body.Model, Proxy: body.Proxy, DailyTokens: body.DailyTokens, Key: old.Key}
	if body.Key != "" {
		st.Key = body.Key
	} else if body.ClearKey {
		st.Key = ""
	}
	if err := ai.Save(r.Context(), s.db, st); err != nil {
		for _, c := range []struct {
			err  error
			code string
		}{{ai.ErrBudget, "ai_budget"}, {ai.ErrURL, "ai_url"}, {ai.ErrProxy, "ai_proxy"}, {ai.ErrNeeds, "ai_needs"}} {
			if errors.Is(err, c.err) {
				writeCode(w, http.StatusBadRequest, c.code, err.Error(),
					"min", strconv.Itoa(ai.MinDailyTokens), "max", strconv.Itoa(ai.MaxDailyTokens))
				return
			}
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.handleAIGet(w, r, model.Admin{})
}

// handleAIReports is GET /api/ai/reports: the newest reports, at most 50,
// of one country when ?country= names it, with the names of the networks
// their findings mention (the reports keep numbers only).
func (s *Server) handleAIReports(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	q := s.db.WithContext(r.Context()).Order("id DESC").Limit(50)
	if c := r.URL.Query().Get("country"); c != "" {
		q = q.Where("country = ?", c)
	}
	out := []ai.Report{}
	if err := q.Find(&out).Error; err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
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
		writeErr(w, http.StatusInternalServerError, err.Error())
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
