// Package alert delivers the detector's alerts to the admin's Telegram (or
// Bale) chat through addon-kit's bot client. Every alert is stored whether
// or not a chat is set; the admin web lists them.
package alert

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
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

// testText is the message the settings page's test sends.
var testText = map[string]string{
	"en": "✅ <b>NX Insight</b>: alerts reach this chat.",
	"fa": "✅ <b>NX Insight</b>: هشدارها به این گفتگو می\u200cرسند.",
	"ru": "✅ <b>NX Insight</b>: оповещения приходят в этот чат.",
	"zh": "✅ <b>NX Insight</b>：告警会发送到此聊天。",
}

// Test sends the test message and returns what the Bot API answered.
func (t *Telegram) Test(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	text, ok := testText[t.Lang]
	if !ok {
		text = testText["en"]
	}
	_, err := t.Bot.Send(ctx, t.Chat, text, nil)
	return err
}

// Live is the sender in force: the settings page replaces it while
// Insight runs, and every alert reads it as it is sent.
type Live struct {
	Names Names
	cur   atomic.Pointer[Telegram]
}

// Set builds the sender for these options; no bot or no chat is none.
func (l *Live) Set(token string, chat int64, proxy, api, lang string) error {
	t, err := NewTelegram(token, chat, proxy, api, lang, l.Names)
	if err != nil {
		return err
	}
	l.cur.Store(t)
	return nil
}

// Current is the sender in force, nil for none.
func (l *Live) Current() *Telegram { return l.cur.Load() }

// Send delivers a through the sender in force, if there is one.
func (l *Live) Send(ctx context.Context, a detect.Alert) {
	if t := l.cur.Load(); t != nil {
		t.Send(ctx, a)
	}
}
