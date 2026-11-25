package settings

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/model"
)

func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "settings.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&model.State{}); err != nil {
		t.Fatal(err)
	}
	return gdb
}

// live is a Live whose Applied records what it was given and, when refuse
// is set, refuses the install's values (language "en").
func live(t *testing.T, gdb *gorm.DB) (*Live, *[]Values, *bool) {
	t.Helper()
	var applied []Values
	refuse := false
	l := &Live{DB: gdb, Install: Values{Language: "en"}, Applied: func(v Values) error {
		if refuse && v.Language == "en" {
			return errors.New("refused")
		}
		applied = append(applied, v)
		return nil
	}}
	if err := l.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	return l, &applied, &refuse
}

// TestASetThatCannotSaveIsUndone: the database refuses the write; the
// previous values are in force again.
func TestASetThatCannotSaveIsUndone(t *testing.T) {
	gdb := openDB(t)
	l, applied, _ := live(t, gdb)
	if err := l.Set(t.Context(), Values{Language: "fa"}); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := gdb.DB()
	_ = sqlDB.Close()
	if err := l.Set(t.Context(), Values{Language: "ru"}); err == nil {
		t.Fatal("a save to a closed database succeeded")
	}
	if v, saved := l.Get(); v.Language != "fa" || !saved {
		t.Fatalf("in force after the failed save: %+v saved %v", v, saved)
	}
	if last := (*applied)[len(*applied)-1]; last.Language != "fa" {
		t.Fatalf("the sender was left on %+v", last)
	}
}

// TestAResetThatCannotApplyKeepsTheSaved: the install's values are
// refused; the admin's stay in force and in the database.
func TestAResetThatCannotApplyKeepsTheSaved(t *testing.T) {
	gdb := openDB(t)
	l, _, refuse := live(t, gdb)
	if err := l.Set(t.Context(), Values{Language: "fa"}); err != nil {
		t.Fatal(err)
	}
	*refuse = true
	if err := l.Reset(t.Context()); err == nil {
		t.Fatal("a refused reset succeeded")
	}
	if v, saved := l.Get(); v.Language != "fa" || !saved {
		t.Fatalf("in force: %+v saved %v", v, saved)
	}
	if v, saved, err := Load(t.Context(), gdb, Values{}); err != nil || !saved || v.Language != "fa" {
		t.Fatalf("saved row: %+v %v %v", v, saved, err)
	}
}

// TestUpdateMergesWithTheValuesInForce: f sees what is in force, and its
// error stops the save.
func TestUpdateMergesWithTheValuesInForce(t *testing.T) {
	l, _, _ := live(t, openDB(t))
	if err := l.Set(t.Context(), Values{Language: "fa", MetricsToken: "0123456789abcdef0123"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Update(t.Context(), func(old Values) (Values, error) {
		old.Language = "ru"
		return old, nil
	}); err != nil {
		t.Fatal(err)
	}
	if v, _ := l.Get(); v.Language != "ru" || v.MetricsToken != "0123456789abcdef0123" {
		t.Fatalf("after update: %+v", v)
	}
	stop := errors.New("stop")
	if err := l.Update(t.Context(), func(old Values) (Values, error) { return Values{Language: "zh"}, stop }); !errors.Is(err, stop) {
		t.Fatalf("err = %v", err)
	}
	if v, _ := l.Get(); v.Language != "ru" {
		t.Fatalf("an update that failed changed %+v", v)
	}
}

// TestABotAPIAddressIsAnHTTPBaseURL: a Bot API mirror is an http(s) host
// with an optional path; no query, fragment, credentials, other scheme or
// missing host is taken.
func TestABotAPIAddressIsAnHTTPBaseURL(t *testing.T) {
	for api, ok := range map[string]bool{
		"https://tg.example.org":         true,
		"https://tg.example.org/mirror/": true,
		"http://10.0.0.1:8081":           true,
		"https://:8080":                  false,
		"https://tg.example.org/?x=1":    false,
		"https://tg.example.org/#top":    false,
		"https://user:pw@tg.example.org": false,
		"ftp://tg.example.org":           false,
		"tg.example.org":                 false,
	} {
		v := Values{TelegramAPI: api}
		if err := v.Check(); (err == nil) != ok {
			t.Errorf("%q: err = %v, want ok %v", api, err, ok)
		}
	}
}
