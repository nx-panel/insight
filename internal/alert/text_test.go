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
	a := detect.Alert{
		Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless", ASN: 44244, Network: "tcp", Reason: "failures",
		Detail: `{"failRatio":0.86,"normalFailRatio":0.03}`,
	}
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
	probed := detect.Alert{
		Kind: detect.KindProbed, NodeID: 1, Inbound: "vless-reality",
		Detail: `{"score":60,"replayed":3,"followUpFail":12,"followNormal":2}`,
	}
	for _, lang := range []string{"en", "fa", "ru", "zh"} {
		got := Text(probed, names, lang)
		if !strings.Contains(got, "fsn&lt;1&gt;") || !strings.Contains(got, "vless-reality") || !strings.Contains(got, "60") ||
			!strings.Contains(got, "3") || !strings.Contains(got, "12") || !strings.Contains(got, "SNI") {
			t.Errorf("%s probed: %q", lang, got)
		}
	}
	if got := Text(detect.Alert{Kind: detect.KindProbed, Detail: `{"score":40,"replayed":2,"followUpFail":3,"followNormal":2}`}, names, "en"); strings.Contains(got, "surge") {
		t.Errorf("a follow-up count under the surge was given as evidence: %q", got)
	}
	down := detect.Alert{Kind: detect.KindTunnelDown, NodeID: 1, Tunnel: "to-de<x>", Detail: `{"tunnelId":3,"origins":["de-1","nl-2"],"unreachable":["nl-2"]}`}
	up := detect.Alert{Kind: detect.KindTunnelUp, NodeID: 1, Tunnel: "to-de", Detail: `{"tunnelId":3,"origins":["de-1"]}`}
	for _, lang := range []string{"en", "fa", "ru", "zh"} {
		got := Text(down, names, lang)
		if !strings.Contains(got, "to-de&lt;x&gt;") || !strings.Contains(got, "fsn&lt;1&gt;") || !strings.Contains(got, "de-1, nl-2") || strings.Count(got, "nl-2") != 2 {
			t.Errorf("%s tunnel.down: %q", lang, got)
		}
		if got := Text(up, names, lang); !strings.Contains(got, "to-de") || !strings.Contains(got, "de-1") || strings.Contains(got, "%!") {
			t.Errorf("%s tunnel.up: %q", lang, got)
		}
		if strings.Contains(got, "%!") {
			t.Errorf("%s tunnel.down has a bad verb: %q", lang, got)
		}
	}
	if !strings.Contains(Text(a, names, "fa"), "مختل") {
		t.Error("fa is not Persian")
	}
}
