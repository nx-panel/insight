package alert

import (
	"encoding/json"
	"fmt"
	"html"

	"github.com/nx-panel/insight/internal/detect"
)

// phrases are an alert's words in one language; %s and %.0f are filled in
// the order the English shows them.
type phrases struct {
	outage, outageEnd, degraded, recovered string
	failures, drop, early                  string
}

var languages = map[string]phrases{
	"en": {
		outage:    "⛔ <b>%s is cut off</b>: every path to it is down on %.0f nodes at once. Probably a shutdown or a whitelist on that network, not a block of your nodes — nothing to rotate.",
		outageEnd: "✅ <b>%s is back</b>: its paths work again.",
		degraded:  "🔴 <b>Path degraded</b>: %s → %s %s/%s. %s",
		recovered: "🟢 <b>Path recovered</b>: %s → %s %s/%s.",
		failures:  "%.0f%% of connections fail the handshake (normally %.0f%%).",
		drop:      "%.0f connections an hour get through (normally %.0f).",
		early:     "%.0f%% of sessions are cut within seconds (normally %.0f%%).",
	},
	"fa": {
		outage:    "⛔ <b>%s قطع است</b>: همهٔ مسیرها به آن هم\u200cزمان روی %.0f نود از کار افتاده\u200cاند. احتمالاً قطع اینترنت یا لیست سفید روی همان شبکه است، نه مسدود شدن نودهای شما — چیزی برای چرخاندن نیست.",
		outageEnd: "✅ <b>%s برگشت</b>: مسیرهایش دوباره کار می\u200cکنند.",
		degraded:  "🔴 <b>مسیر مختل شد</b>: %s ← %s %s/%s. %s",
		recovered: "🟢 <b>مسیر برگشت</b>: %s ← %s %s/%s.",
		failures:  "%.0f٪ اتصال\u200cها در handshake رد می\u200cشوند (معمولاً %.0f٪).",
		drop:      "ساعتی %.0f اتصال می\u200cرسد (معمولاً %.0f).",
		early:     "%.0f٪ جلسه\u200cها در چند ثانیه قطع می\u200cشوند (معمولاً %.0f٪).",
	},
	"ru": {
		outage:    "⛔ <b>%s отрезан</b>: все пути к нему не работают одновременно на %.0f узлах. Скорее всего, отключение или белый список в этой сети, а не блокировка ваших узлов — менять нечего.",
		outageEnd: "✅ <b>%s снова доступен</b>: его пути работают.",
		degraded:  "🔴 <b>Путь деградировал</b>: %s → %s %s/%s. %s",
		recovered: "🟢 <b>Путь восстановлен</b>: %s → %s %s/%s.",
		failures:  "%.0f%% соединений не проходят рукопожатие (обычно %.0f%%).",
		drop:      "Проходит %.0f соединений в час (обычно %.0f).",
		early:     "%.0f%% сессий обрываются за секунды (обычно %.0f%%).",
	},
	"zh": {
		outage:    "⛔ <b>%s 已被切断</b>：到它的所有路径同时在 %.0f 个节点上中断。很可能是该网络断网或启用白名单，而不是您的节点被封锁——无需轮换。",
		outageEnd: "✅ <b>%s 已恢复</b>：其路径重新可用。",
		degraded:  "🔴 <b>路径受阻</b>：%s → %s %s/%s。%s",
		recovered: "🟢 <b>路径已恢复</b>：%s → %s %s/%s。",
		failures:  "%.0f%% 的连接握手失败（通常为 %.0f%%）。",
		drop:      "每小时有 %.0f 个连接通过（通常为 %.0f）。",
		early:     "%.0f%% 的会话在几秒内被切断（通常为 %.0f%%）。",
	},
}

// Text is an alert as a message (Telegram HTML) in lang (en when unknown).
func Text(a detect.Alert, n Names, lang string) string {
	p, ok := languages[lang]
	if !ok {
		p = languages["en"]
	}
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
		return fmt.Sprintf(p.outage, e(asn), d["nodes"])
	case detect.KindOutageEnd:
		return fmt.Sprintf(p.outageEnd, e(asn))
	case detect.KindDegraded:
		return fmt.Sprintf(p.degraded, e(asn), e(node), e(a.Inbound), e(a.Network), e(reason(p, a.Reason, d)))
	case detect.KindRecovered:
		return fmt.Sprintf(p.recovered, e(asn), e(node), e(a.Inbound), e(a.Network))
	}
	return e(a.Kind)
}

func reason(p phrases, r string, d map[string]float64) string {
	switch r {
	case "failures":
		return fmt.Sprintf(p.failures, 100*d["failRatio"], 100*d["normalFailRatio"])
	case "drop":
		return fmt.Sprintf(p.drop, d["authedPerHour"], d["normalAuthedPerHour"])
	case "early_close":
		return fmt.Sprintf(p.early, 100*d["earlyRatio"], 100*d["normalEarlyRatio"])
	}
	return r
}
