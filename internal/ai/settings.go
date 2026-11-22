// Package ai is Mode A of nx-panel docs/path-telemetry.md §4.4 and §4.8: the
// admin's own model — any OpenAI-compatible API with their key, or a local
// Ollama at no cost — reads a compact table of this panel's paths once a day
// per client country, and again when the detector raises an alert there, and
// answers with structured findings: codes and parameters the admin web
// renders in its four languages (no translation calls, no prose).
//
// The model never sits on a request path and never sees raw data: what is
// sent is per client network (ASN), node id and inbound tag, as counts and
// ratios — no client prefix or address, no node address or name. Nothing goes
// to NX. Tiers 0 and 1 (the detector, the scores, the hints) are complete
// without it; it only adds a reading across them.
package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nx-panel/addon-kit/telegram"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/model"
)

// Settings are the admin's model, set in the admin web and kept in
// Insight's own database. The key is never sent back to the web.
type Settings struct {
	Enabled bool `json:"enabled"`
	// URL is the API's base, the part before /chat/completions:
	// https://api.openai.com/v1, http://127.0.0.1:11434/v1 for Ollama.
	URL   string `json:"url"`
	Model string `json:"model"`
	Key   string `json:"key,omitempty"`
	// Proxy is a SOCKS5 or HTTP proxy for a server that cannot reach the
	// provider directly.
	Proxy string `json:"proxy"`
	// DailyTokens is the budget: past it, no call is made until the next
	// UTC day and the tiers below carry on alone.
	DailyTokens int `json:"dailyTokens"`
}

// Budget bounds and default.
const (
	DefaultDailyTokens = 100_000
	MinDailyTokens     = 5_000
	MaxDailyTokens     = 10_000_000
)

const stateSettings = "ai_settings"

// Load reads the settings; none saved is Mode A off.
func Load(ctx context.Context, gdb *gorm.DB) (Settings, error) {
	var st model.State
	if err := gdb.WithContext(ctx).Where("key = ?", stateSettings).Limit(1).Find(&st).Error; err != nil {
		return Settings{}, err
	}
	s := Settings{DailyTokens: DefaultDailyTokens}
	if st.Value == "" {
		return s, nil
	}
	if err := json.Unmarshal([]byte(st.Value), &s); err != nil {
		return Settings{DailyTokens: DefaultDailyTokens}, nil // a damaged row is off
	}
	return s, nil
}

// SameProvider reports whether a saved key may be kept for s: the same API
// scheme, host and port over the same proxy. Anywhere else the key has to be
// typed again — otherwise whoever holds an admin session could point the
// address at a server of their own and have the saved key sent there. The
// two are compared as parsed, so a spelling a URL library writes differently
// (an upper-case scheme, a password's escaping) is not a change.
func (s Settings) SameProvider(old Settings) bool {
	a, errA := url.Parse(strings.TrimSpace(s.URL))
	b, errB := url.Parse(strings.TrimSpace(old.URL))
	return errA == nil && errB == nil && a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host) &&
		sameProxy(s.Proxy, old.Proxy)
}

func sameProxy(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == b {
		return true
	}
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)
	if errA != nil || errB != nil || a == "" || b == "" {
		return false
	}
	pa, _ := ua.User.Password()
	pb, _ := ub.User.Password()
	return ua.Scheme == ub.Scheme && strings.EqualFold(ua.Host, ub.Host) && ua.User.Username() == ub.User.Username() && pa == pb
}

// maskedPassword stands in for a proxy's password in what the web is shown.
const maskedPassword = "********"

// MaskProxy is a proxy URL without its password.
func MaskProxy(proxy string) string {
	u, err := url.Parse(proxy)
	if err != nil || u.User == nil {
		return proxy
	}
	if _, has := u.User.Password(); !has {
		return proxy
	}
	u.User = url.UserPassword(u.User.Username(), maskedPassword)
	// String escapes the asterisks; the admin is shown the mask itself.
	return strings.Replace(u.String(), url.UserPassword("", maskedPassword).String(), ":"+maskedPassword, 1)
}

// UnmaskProxy is the saved proxy when the web sent it back with the mask
// still in it — the same scheme, host and user — and what the web sent
// otherwise: a proxy that differs in any of them gets no password it was
// not given.
func UnmaskProxy(proxy, saved string) string {
	u, err := url.Parse(strings.TrimSpace(proxy))
	if err != nil || u.User == nil {
		return proxy
	}
	if p, _ := u.User.Password(); p != maskedPassword {
		return proxy
	}
	old, err := url.Parse(strings.TrimSpace(saved))
	if err != nil || old.User == nil || old.Scheme != u.Scheme || !strings.EqualFold(old.Host, u.Host) || old.User.Username() != u.User.Username() {
		return proxy
	}
	return saved
}

// Save writes the settings after Validate.
func Save(ctx context.Context, gdb *gorm.DB, s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(s)
	return model.PutState(gdb.WithContext(ctx), stateSettings, string(raw))
}

// The settings the admin has to correct, one error each so the admin web
// can say which in its own language.
var (
	ErrBudget = errors.New("the daily budget is out of range")
	ErrURL    = errors.New("the API address must be an http or https URL")
	ErrProxy  = errors.New("the proxy must be a socks5, socks5h, http or https URL")
	ErrNeeds  = errors.New("an API address and a model are needed to turn it on")
)

// Validate checks what can be checked without calling the provider.
func (s *Settings) Validate() error {
	s.URL = strings.TrimRight(strings.TrimSpace(s.URL), "/")
	s.Model = strings.TrimSpace(s.Model)
	s.Proxy = strings.TrimSpace(s.Proxy)
	if s.DailyTokens == 0 {
		s.DailyTokens = DefaultDailyTokens
	}
	if s.DailyTokens < MinDailyTokens || s.DailyTokens > MaxDailyTokens {
		return fmt.Errorf("%w: %d–%d tokens", ErrBudget, MinDailyTokens, MaxDailyTokens)
	}
	if s.URL != "" {
		u, err := url.Parse(s.URL)
		// No query or fragment: "/chat/completions" is appended to it, and
		// a "?" would turn that into a parameter of some other path. No
		// credentials in it either: the key has its own field.
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.ContainsAny(s.URL, "?#") || u.User != nil {
			return ErrURL
		}
	}
	if s.Proxy != "" {
		if telegram.ValidProxy(s.Proxy) != nil {
			return ErrProxy
		}
	}
	if s.Enabled && (s.URL == "" || s.Model == "") {
		return ErrNeeds
	}
	return nil
}
