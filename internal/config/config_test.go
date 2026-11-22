package config

import "testing"

func TestParseCountries(t *testing.T) {
	got, err := ParseCountries(" ir, RU,cn ,ir,")
	if err != nil || len(got) != 3 || got[0] != "IR" || got[2] != "CN" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"IRN", "I", "1R"} {
		if _, err := ParseCountries(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDefaults(t *testing.T) {
	t.Setenv("NX_DATA_DIR", t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != "8099" || c.Driver != DriverSQLite || c.ASNURL != DefaultASNURL || len(c.RegionCountries) != 3 {
		t.Fatalf("defaults = %+v", c)
	}
	t.Setenv("NX_OPT_DATABASE", "postgres")
	if _, err := Load(); err == nil {
		t.Fatal("postgres without a DSN was accepted")
	}
}
