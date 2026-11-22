// Package config reads Insight's configuration from the environment, the
// way the install passes it: the answers to the manifest's options as
// NX_OPT_<KEY>, beside NX_DATA_DIR and NX_MANIFEST_FILE.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/addon-kit/web"
)

// The database drivers the manifest's "database" option offers.
const (
	DriverSQLite   = "sqlite"
	DriverPostgres = "postgres"
)

// The network-information sources (nx-panel docs/path-telemetry.md P5, P17):
// each install downloads them itself, from where their publishers put them.
// The two options exist so a mirror can be named later without a release.
const (
	// DefaultASNURL is iptoasn.com's combined IPv4+IPv6 ranges, refreshed
	// hourly by its publisher.
	DefaultASNURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"
	// DefaultCityURL is DB-IP's free City Lite, published monthly under
	// CC BY 4.0; {month} is the YYYY-MM of the release asked for.
	DefaultCityURL = "https://download.db-ip.com/free/dbip-city-lite-{month}.csv.gz"
)

// DefaultRegionCountries are the client countries whose regions are kept:
// the markets the product is for (Iran, Russia, China). A client elsewhere
// still gets its ASN and country, only no region.
var DefaultRegionCountries = []string{"IR", "RU", "CN"}

// Config is what Insight starts with.
type Config struct {
	Port     string
	DataDir  string
	BasePath string
	// PublicURL is the address the admins open Insight at.
	PublicURL string
	// HTTPS is how Insight serves that address itself (web.HTTPSModes).
	HTTPS         string
	HTTPListen    string
	ACMEDirectory string
	ACMEInsecure  bool
	// Driver is sqlite or postgres. For SQLite, DSN is the file in DataDir;
	// for PostgreSQL it is the install's connection string.
	Driver string
	DSN    string
	// AdminUsername and AdminPassword make the first admin when there is
	// none.
	AdminUsername string
	AdminPassword string
	ManifestFile  string
	// TrustedProxies are the reverse proxies in front of Insight whose
	// X-Forwarded-For is believed; empty trusts none.
	TrustedProxies string
	// Listen is the address the port is bound on; empty is every interface.
	Listen string
	// ASNURL and CityURL are where the network information is downloaded
	// from; RegionCountries the client countries whose regions are kept.
	ASNURL          string
	CityURL         string
	RegionCountries []string
	// Telegram (or Bale) for the alerts: a bot token and the admin's chat
	// id; a proxy for a server that cannot reach Telegram, and the Bot API
	// address for Bale or a mirror. No token: the alerts are only stored.
	TelegramToken string
	TelegramChat  int64
	TelegramProxy string
	TelegramAPI   string
}

// Load reads the environment.
func Load() (Config, error) {
	c := Config{
		Port:           option("port", "8099"),
		BasePath:       addon.Option("base_path"),
		PublicURL:      strings.TrimRight(strings.TrimSpace(addon.Option("public_url")), "/"),
		HTTPS:          strings.ToLower(option("https", web.HTTPSOff)),
		HTTPListen:     env("NX_HTTP_LISTEN", ":80"),
		ACMEDirectory:  os.Getenv("NX_ACME_DIRECTORY"),
		ACMEInsecure:   os.Getenv("NX_ACME_INSECURE") == "1",
		DataDir:        env("NX_DATA_DIR", "data"),
		Driver:         strings.ToLower(option("database", DriverSQLite)),
		DSN:            strings.TrimSpace(addon.Option("database_dsn")),
		AdminUsername:  option("admin_username", "admin"),
		AdminPassword:  addon.Option("admin_password"),
		ManifestFile:   os.Getenv("NX_MANIFEST_FILE"),
		TrustedProxies: strings.TrimSpace(addon.Option("trusted_proxies")),
		Listen:         strings.Trim(strings.TrimSpace(addon.Option("listen")), "[]"),
		ASNURL:         option("asn_url", DefaultASNURL),
		CityURL:        option("city_url", DefaultCityURL),
	}
	c.TelegramToken = strings.TrimSpace(addon.Option("telegram_token"))
	c.TelegramProxy = strings.TrimSpace(addon.Option("telegram_proxy"))
	c.TelegramAPI = strings.TrimSpace(addon.Option("telegram_api"))
	if chat := strings.TrimSpace(addon.Option("telegram_chat")); chat != "" {
		n, err := strconv.ParseInt(chat, 10, 64)
		if err != nil {
			return c, fmt.Errorf("telegram_chat must be a chat id (a number): %q", chat)
		}
		c.TelegramChat = n
	}
	regions, err := ParseCountries(option("region_countries", strings.Join(DefaultRegionCountries, ",")))
	if err != nil {
		return c, fmt.Errorf("region_countries: %w", err)
	}
	c.RegionCountries = regions
	if !slices.Contains(web.HTTPSModes, c.HTTPS) {
		return c, fmt.Errorf("https must be one of %s", strings.Join(web.HTTPSModes, ", "))
	}
	base, err := web.BasePath(c.BasePath)
	if err != nil {
		return c, fmt.Errorf("base_path: %w", err)
	}
	c.BasePath = base
	if c.Listen != "" {
		if _, err := netip.ParseAddr(c.Listen); err != nil {
			return c, fmt.Errorf("listen must be an IP address of this server, such as 127.0.0.1, or empty for every interface: %q", c.Listen)
		}
	}
	switch c.Driver {
	case DriverSQLite:
		c.DSN = filepath.Join(c.DataDir, "insight.db")
	case DriverPostgres:
		if c.DSN == "" {
			return c, errors.New("database is postgres but database_dsn (NX_OPT_DATABASE_DSN) is empty")
		}
	default:
		return c, errors.New("database must be sqlite or postgres")
	}
	return c, nil
}

// ParseCountries reads a comma-separated list of ISO 3166-1 alpha-2 codes.
func ParseCountries(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		cc := strings.ToUpper(strings.TrimSpace(part))
		if cc == "" {
			continue
		}
		if len(cc) != 2 || cc[0] < 'A' || cc[0] > 'Z' || cc[1] < 'A' || cc[1] > 'Z' {
			return nil, fmt.Errorf("%q is not a two-letter country code", part)
		}
		if !slices.Contains(out, cc) {
			out = append(out, cc)
		}
	}
	return out, nil
}

func option(key, def string) string {
	if v := strings.TrimSpace(addon.Option(key)); v != "" {
		return v
	}
	return def
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Addr is where the port listens.
func (c Config) Addr() string { return net.JoinHostPort(c.Listen, c.Port) }
