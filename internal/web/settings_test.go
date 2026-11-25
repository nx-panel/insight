package web

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestTheSettingsPage: the install's values hold until a save; a secret is
// never sent back, only whether it is set; a bad value is refused with its
// code; the metrics token is taken without a restart; the bot's token is
// not kept when the Bot API address moves; a reset brings the install's
// values back.
func TestTheSettingsPage(t *testing.T) {
	e := newEnv(t)
	e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "admin-secret-1"}, nil)

	var v map[string]any
	if code := e.call("GET", "/api/settings", nil, &v); code != http.StatusOK || v["saved"] != false || v["metricsTokenSet"] != false {
		t.Fatalf("first read = %d %v", code, v)
	}
	scrape := func(token string) int {
		req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := scrape("x"); code != http.StatusNotFound {
		t.Fatalf("/metrics with no token set = %d", code)
	}

	put := func(body map[string]any) (int, map[string]any) {
		var out map[string]any
		return e.call("PUT", "/api/settings", body, &out), out
	}
	if code, out := put(map[string]any{"language": "fa", "metricsToken": "short"}); code != http.StatusBadRequest || out["code"] != "settings_metrics" {
		t.Fatalf("a short metrics token = %d %v", code, out)
	}
	if code, out := put(map[string]any{"language": "xx"}); code != http.StatusBadRequest || out["code"] != "settings_language" {
		t.Fatalf("an unknown language = %d %v", code, out)
	}
	token := "a-metrics-token-long-enough"
	if code, out := put(map[string]any{"language": "fa", "metricsToken": token}); code != http.StatusOK || out["saved"] != true || out["metricsTokenSet"] != true || out["language"] != "fa" {
		t.Fatalf("save = %d %v", code, out)
	}
	if code := scrape(token); code != http.StatusOK {
		t.Fatalf("/metrics with the saved token = %d", code)
	}
	if code := scrape("wrong-token-long-enough"); code != http.StatusUnauthorized {
		t.Fatalf("/metrics with another token = %d", code)
	}

	if code, out := put(map[string]any{"language": "fa", "telegramToken": "123:abc"}); code != http.StatusBadRequest || out["code"] != "settings_chat" {
		t.Fatalf("a bot with no chat = %d %v", code, out)
	}
	if code, out := put(map[string]any{"language": "fa", "telegramToken": "123:abc", "telegramChat": "-100123"}); code != http.StatusOK || out["telegramTokenSet"] != true || out["metricsTokenSet"] != true {
		t.Fatalf("a bot = %d %v", code, out)
	}
	var raw strings.Builder
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+"/api/settings", nil)
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(&raw, resp.Body)
	resp.Body.Close()
	if strings.Contains(raw.String(), "123:abc") || strings.Contains(raw.String(), token) {
		t.Fatalf("a secret went back to the web: %s", raw.String())
	}
	if code, out := put(map[string]any{"language": "fa", "telegramChat": "-100123", "telegramApi": "https://elsewhere.example"}); code != http.StatusBadRequest || out["code"] != "settings_retype_token" {
		t.Fatalf("the Bot API moved with the saved token = %d %v", code, out)
	}
	if code, out := put(map[string]any{"language": "fa", "telegramChat": "-100123"}); code != http.StatusOK || out["telegramTokenSet"] != true {
		t.Fatalf("an edit keeping the token = %d %v", code, out)
	}

	if code := e.call("DELETE", "/api/settings", nil, &v); code != http.StatusOK || v["saved"] != false || v["metricsTokenSet"] != false || v["telegramTokenSet"] != false {
		t.Fatalf("reset = %d %v", code, v)
	}
	if code := scrape(token); code != http.StatusNotFound {
		t.Fatalf("/metrics after the reset = %d", code)
	}
}
