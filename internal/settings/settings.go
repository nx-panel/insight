// Package settings holds what the admin may change in the admin web while
// Insight runs: where alerts go (a Telegram or Bale bot and chat, through a
// proxy or a Bot API mirror), the language they are written in, and the
// token /metrics asks for. The installer's options are the starting values;
// once the admin saves the settings page, the saved values win and the
// install's are no longer read. Everything else the installer asked — the
// port, the address, the database, HTTPS — stays an install option, since
// changing it means a restart and possibly a different address.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/nx-panel/addon-kit/telegram"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/model"
)

// Values are the settings the admin web changes.
type Values struct {
	TelegramToken string `json:"telegramToken,omitempty"`
	TelegramChat  int64  `json:"telegramChat"`
	TelegramProxy string `json:"telegramProxy"`
	TelegramAPI   string `json:"telegramApi"`
	// Language is the alerts' language: en, fa, ru or zh.
	Language     string `json:"language"`
	MetricsToken string `json:"metricsToken,omitempty"`
}

// Languages are the alert languages.
var Languages = []string{"en", "fa", "ru", "zh"}

// The reasons Check refuses a value, for the web's own wording.
var (
	ErrLanguage = errors.New("the language must be en, fa, ru or zh")
	ErrMetrics  = fmt.Errorf("the metrics token must be %d characters or more", config.MinMetricsToken)
	ErrProxy    = errors.New("the proxy must be a socks5, http or https URL")
	ErrAPI      = errors.New("the Bot API address must be an http or https URL")
	ErrChat     = errors.New("a bot needs a chat id, and a chat id a bot")
)

// FromConfig is the install's values: what holds until the admin saves.
func FromConfig(c config.Config) Values {
	return Values{
		TelegramToken: c.TelegramToken, TelegramChat: c.TelegramChat,
		TelegramProxy: c.TelegramProxy, TelegramAPI: c.TelegramAPI,
		Language: c.Language, MetricsToken: c.MetricsToken,
	}
}

// Check trims v and refuses what Insight could not use.
func (v *Values) Check() error {
	v.TelegramToken = strings.TrimSpace(v.TelegramToken)
	v.TelegramProxy = strings.TrimSpace(v.TelegramProxy)
	v.TelegramAPI = strings.TrimRight(strings.TrimSpace(v.TelegramAPI), "/")
	v.MetricsToken = strings.TrimSpace(v.MetricsToken)
	v.Language = strings.ToLower(strings.TrimSpace(v.Language))
	if v.Language == "" {
		v.Language = "en"
	}
	if !slices.Contains(Languages, v.Language) {
		return ErrLanguage
	}
	if v.MetricsToken != "" && len(v.MetricsToken) < config.MinMetricsToken {
		return ErrMetrics
	}
	if (v.TelegramToken == "") != (v.TelegramChat == 0) {
		return ErrChat
	}
	if v.TelegramProxy != "" {
		if _, err := telegram.HTTPClient(v.TelegramProxy); err != nil {
			return ErrProxy
		}
	}
	if v.TelegramAPI != "" && !strings.HasPrefix(v.TelegramAPI, "https://") && !strings.HasPrefix(v.TelegramAPI, "http://") {
		return ErrAPI
	}
	return nil
}

const stateKey = "settings"

// Load reads the saved settings; saved is false while the admin has never
// saved them, and def (the install's) is returned.
func Load(ctx context.Context, gdb *gorm.DB, def Values) (v Values, saved bool, err error) {
	var st model.State
	if err := gdb.WithContext(ctx).Where("key = ?", stateKey).Limit(1).Find(&st).Error; err != nil {
		return def, false, err
	}
	if st.Value == "" {
		return def, false, nil
	}
	if err := json.Unmarshal([]byte(st.Value), &v); err != nil {
		return def, false, nil // a damaged row: the install's values
	}
	return v, true, nil
}

// Save writes v after checking it.
func Save(ctx context.Context, gdb *gorm.DB, v Values) error {
	if err := v.Check(); err != nil {
		return err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return gdb.WithContext(ctx).Save(&model.State{Key: stateKey, Value: string(raw)}).Error
}

// Live is the settings in force, read by whatever uses them on every use
// and replaced by the settings page without a restart.
type Live struct {
	DB      *gorm.DB
	Install Values
	// Applied is called with the values in force after a load or a save.
	Applied func(Values) error

	mu    sync.RWMutex
	cur   Values
	saved bool
}

// Start reads the saved settings (or keeps the install's) and applies them.
func (l *Live) Start(ctx context.Context) error {
	v, saved, err := Load(ctx, l.DB, l.Install)
	if err != nil {
		return err
	}
	return l.apply(v, saved)
}

func (l *Live) apply(v Values, saved bool) error {
	if l.Applied != nil {
		if err := l.Applied(v); err != nil {
			return err
		}
	}
	l.mu.Lock()
	l.cur, l.saved = v, saved
	l.mu.Unlock()
	return nil
}

// Get is the values in force and whether they are the admin's.
func (l *Live) Get() (Values, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cur, l.saved
}

// MetricsToken is the token /metrics asks for now.
func (l *Live) MetricsToken() string {
	v, _ := l.Get()
	return v.MetricsToken
}

// Set checks, saves and applies v.
func (l *Live) Set(ctx context.Context, v Values) error {
	if err := v.Check(); err != nil {
		return err
	}
	if err := Save(ctx, l.DB, v); err != nil {
		return err
	}
	return l.apply(v, true)
}

// Reset forgets the admin's settings: the install's are in force again.
func (l *Live) Reset(ctx context.Context) error {
	if err := l.DB.WithContext(ctx).Where("key = ?", stateKey).Delete(&model.State{}).Error; err != nil {
		return err
	}
	return l.apply(l.Install, false)
}
