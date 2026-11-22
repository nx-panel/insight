// Package alert delivers the detector's alerts to the admin's Telegram (or
// Bale) chat through addon-kit's bot client. Every alert is stored whether
// or not a chat is set; the admin web lists them (PT6).
package alert

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/nx-panel/addon-kit/telegram"
	"github.com/nx-panel/insight/internal/detect"
)

// Names turns ids into what an admin reads.
type Names struct {
	Node func(id uint) string
	ASN  func(asn uint32) string
}

// Telegram sends to one chat.
type Telegram struct {
	Bot   telegram.Bot
	Chat  int64
	Names Names
	Lang  string
}

// NewTelegram is a sender for the install's options, or nil when no bot is
// set. proxy is a SOCKS5 or HTTP proxy URL for a server that cannot reach
// Telegram directly; api a Bot API address (Bale's, a mirror) or "".
func NewTelegram(token string, chat int64, proxy, api, lang string, names Names) (*Telegram, error) {
	if token == "" || chat == 0 {
		return nil, nil
	}
	var hc *http.Client
	if proxy != "" {
		var err error
		if hc, err = telegram.HTTPClient(proxy); err != nil {
			return nil, err
		}
	}
	return &Telegram{Bot: telegram.Bot{Token: token, APIBase: api, HTTP: hc}, Chat: chat, Names: names, Lang: lang}, nil
}

// Send delivers one alert; a failure is logged, the alert stays stored.
func (t *Telegram) Send(ctx context.Context, a detect.Alert) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := t.Bot.Send(ctx, t.Chat, Text(a, t.Names, t.Lang), nil); err != nil {
		log.Printf("alert: telegram: %v", err)
	}
}
