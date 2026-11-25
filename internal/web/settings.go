package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/alert"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/settings"
)

// The settings page (internal/settings): where alerts go, their language,
// the metrics token — and, read-only, the options the installer set.

func (s *Server) mountSettings(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/settings", s.signedIn(s.handleSettingsGet))
	mux.HandleFunc("PUT /api/settings", s.signedIn(s.handleSettingsPut))
	mux.HandleFunc("DELETE /api/settings", s.signedIn(s.handleSettingsReset))
	mux.HandleFunc("POST /api/settings/telegram/test", s.signedIn(s.handleTelegramTest))
}

// installView is what the installer set and only it changes: the address,
// the database, HTTPS. Secrets are left out.
type installView struct {
	Port            string   `json:"port"`
	BasePath        string   `json:"basePath"`
	PublicURL       string   `json:"publicUrl"`
	HTTPS           string   `json:"https"`
	Database        string   `json:"database"`
	AdminUsername   string   `json:"adminUsername"`
	RegionCountries []string `json:"regionCountries"`
	ASNURL          string   `json:"asnUrl"`
	CityURL         string   `json:"cityUrl"`
	TrustedProxies  string   `json:"trustedProxies"`
}

// settingsView is the settings as the web sees them: a secret only as
// whether one is set, a proxy's password masked.
type settingsView struct {
	Saved            bool        `json:"saved"`
	TelegramTokenSet bool        `json:"telegramTokenSet"`
	TelegramChat     string      `json:"telegramChat"`
	TelegramProxy    string      `json:"telegramProxy"`
	TelegramAPI      string      `json:"telegramApi"`
	Language         string      `json:"language"`
	MetricsTokenSet  bool        `json:"metricsTokenSet"`
	MetricsMin       int         `json:"metricsMin"`
	Install          installView `json:"install"`
}

func (s *Server) settingsView() settingsView {
	v, saved := s.settings.Get()
	chat := ""
	if v.TelegramChat != 0 {
		chat = strconv.FormatInt(v.TelegramChat, 10)
	}
	return settingsView{
		Saved: saved, TelegramTokenSet: v.TelegramToken != "", TelegramChat: chat,
		TelegramProxy: ai.MaskProxy(v.TelegramProxy), TelegramAPI: v.TelegramAPI,
		Language: v.Language, MetricsTokenSet: v.MetricsToken != "", MetricsMin: config.MinMetricsToken,
		Install: installView{
			Port: s.cfg.Port, BasePath: s.cfg.BasePath, PublicURL: s.cfg.PublicURL, HTTPS: s.cfg.HTTPS,
			Database: s.cfg.Driver, AdminUsername: s.cfg.AdminUsername,
			RegionCountries: append([]string{}, s.cfg.RegionCountries...),
			ASNURL:          s.cfg.ASNURL, CityURL: s.cfg.CityURL, TrustedProxies: s.cfg.TrustedProxies,
		},
	}
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, _ *http.Request, _ model.Admin) {
	if s.settings == nil {
		writeCode(w, http.StatusNotFound, "not_found", "settings are not available")
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView())
}

// handleSettingsPut is PUT /api/settings. A secret left empty keeps the
// saved one unless its clear flag is set; the bot's token is not kept when
// the Bot API address moves, since the token would then be sent to
// wherever the new address points — it has to be typed again.
func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.settings == nil {
		writeCode(w, http.StatusNotFound, "not_found", "settings are not available")
		return
	}
	var body struct {
		TelegramToken      string `json:"telegramToken"`
		ClearTelegramToken bool   `json:"clearTelegramToken"`
		TelegramChat       string `json:"telegramChat"`
		TelegramProxy      string `json:"telegramProxy"`
		TelegramAPI        string `json:"telegramApi"`
		Language           string `json:"language"`
		MetricsToken       string `json:"metricsToken"`
		ClearMetricsToken  bool   `json:"clearMetricsToken"`
	}
	if decode(r, &body) != nil {
		badBody(w)
		return
	}
	var chat int64
	if body.TelegramChat != "" {
		var err error
		if chat, err = strconv.ParseInt(body.TelegramChat, 10, 64); err != nil {
			writeCode(w, http.StatusBadRequest, "settings_chat_id", "the chat id must be a number")
			return
		}
	}
	err := s.settings.Update(r.Context(), func(old settings.Values) (settings.Values, error) {
		v := settings.Values{
			TelegramToken: old.TelegramToken, TelegramChat: chat, TelegramProxy: ai.UnmaskProxy(body.TelegramProxy, old.TelegramProxy),
			TelegramAPI: body.TelegramAPI, Language: body.Language, MetricsToken: old.MetricsToken,
		}
		switch {
		case body.ClearTelegramToken: // wins over a token typed alongside
			v.TelegramToken = ""
		case body.TelegramToken != "":
			v.TelegramToken = body.TelegramToken
		case v.TelegramToken != "" && trimAPI(body.TelegramAPI) != trimAPI(old.TelegramAPI):
			return v, errRetypeToken
		}
		switch {
		case body.MetricsToken != "":
			v.MetricsToken = body.MetricsToken
		case body.ClearMetricsToken:
			v.MetricsToken = ""
		}
		return v, nil
	})
	if err != nil {
		for _, c := range []struct {
			err    error
			code   string
			params []string
		}{
			{errRetypeToken, "settings_retype_token", nil},
			{settings.ErrLanguage, "settings_language", nil},
			{settings.ErrMetrics, "settings_metrics", []string{"min", strconv.Itoa(config.MinMetricsToken)}},
			{settings.ErrProxy, "settings_proxy", nil},
			{settings.ErrAPI, "settings_api", nil},
			{settings.ErrChat, "settings_chat", nil},
		} {
			if errors.Is(err, c.err) {
				writeCode(w, http.StatusBadRequest, c.code, err.Error(), c.params...)
				return
			}
		}
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView())
}

// errRetypeToken is a kept token whose Bot API address moved.
var errRetypeToken = errors.New("the Bot API address changed: type the bot's token again")

func trimAPI(u string) string { return strings.TrimRight(strings.TrimSpace(u), "/") }

// handleSettingsReset is DELETE /api/settings: the installer's options are
// in force again.
func (s *Server) handleSettingsReset(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	if s.settings == nil {
		writeCode(w, http.StatusNotFound, "not_found", "settings are not available")
		return
	}
	if err := s.settings.Reset(r.Context()); err != nil {
		serverError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsView())
}

// handleTelegramTest is POST /api/settings/telegram/test: one message to
// the chat in force, at most every ten seconds; the Bot API's refusal is
// passed on as it came, since it is what says what is wrong.
func (s *Server) handleTelegramTest(w http.ResponseWriter, r *http.Request, _ model.Admin) {
	var cur *alert.Telegram
	if s.alerts != nil {
		cur = s.alerts.Current()
	}
	if cur == nil {
		writeCode(w, http.StatusConflict, "telegram_off", "no bot and chat are set")
		return
	}
	if !s.tested.allow(10 * time.Second) {
		writeCode(w, http.StatusTooManyRequests, "too_soon", "asked less than ten seconds ago")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	if err := cur.Test(ctx); err != nil {
		writeCode(w, http.StatusBadGateway, "telegram_failed", err.Error(), "error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
