// Package alert delivers the detector's alerts to the admin's Telegram (or
// Bale) chat through addon-kit's bot client. Every alert is stored whether
// or not a chat is set; the admin web lists them (PT6).
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
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
}

// NewTelegram is a sender for the install's options, or nil when no bot is
// set. proxy is a SOCKS5 or HTTP proxy URL for a server that cannot reach
// Telegram directly; api a Bot API address (Bale's, a mirror) or "".
func NewTelegram(token string, chat int64, proxy, api string, names Names) (*Telegram, error) {
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
	return &Telegram{Bot: telegram.Bot{Token: token, APIBase: api, HTTP: hc}, Chat: chat, Names: names}, nil
}

// Send delivers one alert; a failure is logged, the alert stays stored.
func (t *Telegram) Send(ctx context.Context, a detect.Alert) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := t.Bot.Send(ctx, t.Chat, Text(a, t.Names), nil); err != nil {
		log.Printf("alert: telegram: %v", err)
	}
}

// Text is an alert as a message (Telegram HTML).
func Text(a detect.Alert, n Names) string {
	asn := fmt.Sprintf("AS%d", a.ASN)
	if n.ASN != nil {
		if org := n.ASN(a.ASN); org != "" {
			asn += " " + org
		}
	}
	node := fmt.Sprintf("#%d", a.NodeID)
	if n.Node != nil {
		if name := n.Node(a.NodeID); name != "" {
			node = name
		}
	}
	var d map[string]float64
	_ = json.Unmarshal([]byte(a.Detail), &d)
	e := html.EscapeString
	switch a.Kind {
	case detect.KindOutage:
		return fmt.Sprintf("⛔ <b>%s is cut off</b>: every path to it is down on %.0f nodes at once. Probably a shutdown or a whitelist on that network, not a block of your nodes — nothing to rotate.", e(asn), d["nodes"])
	case detect.KindOutageEnd:
		return fmt.Sprintf("✅ <b>%s is back</b>: its paths work again.", e(asn))
	case detect.KindDegraded:
		return fmt.Sprintf("🔴 <b>Path degraded</b>: %s → %s %s/%s. %s", e(asn), e(node), e(a.Inbound), e(a.Network), e(reason(a.Reason, d)))
	case detect.KindRecovered:
		return fmt.Sprintf("🟢 <b>Path recovered</b>: %s → %s %s/%s.", e(asn), e(node), e(a.Inbound), e(a.Network))
	}
	return e(a.Kind)
}

func reason(r string, d map[string]float64) string {
	switch r {
	case "failures":
		return fmt.Sprintf("%.0f%% of connections fail the handshake (normally %.0f%%).", 100*d["failRatio"], 100*d["normalFailRatio"])
	case "drop":
		return fmt.Sprintf("%.0f connections an hour get through (normally %.0f).", d["authedPerHour"], d["normalAuthedPerHour"])
	case "early_close":
		return fmt.Sprintf("%.0f%% of sessions are cut within seconds (normally %.0f%%).", 100*d["earlyRatio"], 100*d["normalEarlyRatio"])
	}
	return strings.TrimSpace(r)
}
