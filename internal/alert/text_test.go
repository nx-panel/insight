package alert

import (
	"strings"
	"testing"

	"github.com/nx-panel/insight/internal/detect"
)

// TestTextInEveryLanguage: every kind reads in each of the four languages,
// with the node's and the ASN's names, the numbers it was judged on, and
// nothing a name holds taken as markup.
func TestTextInEveryLanguage(t *testing.T) {
	names := Names{Node: func(uint) string { return "fsn<1>" }, ASN: func(uint32) string { return "MCI" }}
	a := detect.Alert{Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless", ASN: 44244, Network: "tcp", Reason: "failures",
		Detail: `{"failRatio":0.86,"normalFailRatio":0.03}`}
	for _, lang := range []string{"en", "fa", "ru", "zh", "xx"} {
		got := Text(a, names, lang)
		if !strings.Contains(got, "AS44244 MCI") || !strings.Contains(got, "fsn&lt;1&gt;") || !strings.Contains(got, "86") {
			t.Errorf("%s: %q", lang, got)
		}
		for _, kind := range []string{detect.KindRecovered, detect.KindOutage, detect.KindOutageEnd} {
			if got := Text(detect.Alert{Kind: kind, ASN: 44244, Detail: `{"nodes":3}`}, names, lang); !strings.Contains(got, "AS44244") {
				t.Errorf("%s %s: %q", lang, kind, got)
			}
		}
	}
	if !strings.Contains(Text(a, names, "fa"), "مختل") {
		t.Error("fa is not Persian")
	}
}
