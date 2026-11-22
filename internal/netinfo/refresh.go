package netinfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// asnEvery is how often the ASN ranges are fetched again. The
	// publisher updates them hourly; a day is fresh enough for paths that
	// change ASN rarely, and keeps the download (a few MB) off every hour.
	asnEvery = 24 * time.Hour
	// cityEvery is how often DB-IP is asked for a newer release; it
	// publishes one a month.
	cityEvery = 7 * 24 * time.Hour
	// retryEvery is the wait after a failed download.
	retryEvery  = time.Hour
	maxDownload = 1 << 30
)

// Sources is where the two files come from and what to keep of the city
// one.
type Sources struct {
	ASNURL  string
	CityURL string // {month} is replaced by YYYY-MM
	// RegionCountries are the client countries whose regions are kept.
	RegionCountries []string
}

// Manager keeps the files in a directory, loads them into a DB, and
// downloads them again on schedule.
type Manager struct {
	DB      *DB
	Dir     string
	Sources Sources
	HTTP    *http.Client
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// OnCity runs after a new city file is in, for the node lookups that
	// scan it.
	OnCity func()
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) asnPath() string  { return filepath.Join(m.Dir, "ip2asn.tsv.gz") }
func (m *Manager) cityPath() string { return filepath.Join(m.Dir, "dbip-city-lite.csv.gz") }

// CityPath is the city file on disk, for ScanCity.
func (m *Manager) CityPath() string { return m.cityPath() }

// LoadLocal loads what the directory already holds, so a restart answers at
// once without a download.
func (m *Manager) LoadLocal() {
	if err := m.loadASN(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("netinfo: asn: %v", err)
	}
	if err := m.loadCity(); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("netinfo: city: %v", err)
	}
}

func (m *Manager) loadASN() error {
	f, err := os.Open(m.asnPath())
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := ReadASN(f)
	if err != nil {
		return err
	}
	m.DB.SetASN(t)
	return nil
}

func (m *Manager) loadCity() error {
	f, err := os.Open(m.cityPath())
	if err != nil {
		return err
	}
	defer f.Close()
	t, err := ReadCity(f, m.Sources.RegionCountries)
	if err != nil {
		return err
	}
	m.DB.SetCity(t)
	return nil
}

// Run refreshes both files for the life of ctx.
func (m *Manager) Run(ctx context.Context) {
	if err := os.MkdirAll(m.Dir, 0o700); err != nil {
		log.Printf("netinfo: %v", err)
		return
	}
	m.LoadLocal()
	nextASN, nextCity := m.due(m.asnPath(), asnEvery), m.due(m.cityPath(), cityEvery)
	for {
		now := m.now()
		if !now.Before(nextASN) {
			if err := m.RefreshASN(ctx); err != nil {
				log.Printf("netinfo: asn: %v", err)
				nextASN = now.Add(retryEvery)
			} else {
				nextASN = now.Add(asnEvery)
			}
		}
		if !now.Before(nextCity) {
			if err := m.RefreshCity(ctx); err != nil {
				log.Printf("netinfo: city: %v", err)
				nextCity = now.Add(retryEvery)
			} else {
				nextCity = now.Add(cityEvery)
			}
		}
		next := nextASN
		if nextCity.Before(next) {
			next = nextCity
		}
		wait := next.Sub(m.now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(max(wait, time.Minute)):
		}
	}
}

// due is when a file next needs fetching: now when it is missing, else its
// age past every.
func (m *Manager) due(path string, every time.Duration) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return m.now()
	}
	return st.ModTime().Add(every)
}

// RefreshASN downloads the ASN ranges, checks they parse, and swaps them in.
func (m *Manager) RefreshASN(ctx context.Context) error {
	tmp, err := m.download(ctx, m.Sources.ASNURL, m.asnPath())
	if err != nil {
		return err
	}
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	t, err := ReadASN(f)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.asnPath()); err != nil {
		return err
	}
	m.DB.SetASN(t)
	return nil
}

// RefreshCity downloads this month's City Lite, or last month's when this
// month's is not out yet, checks it parses, and swaps it in.
func (m *Manager) RefreshCity(ctx context.Context) error {
	now := m.now().UTC()
	var lastErr error
	for _, month := range []time.Time{now, now.AddDate(0, -1, 0)} {
		url := strings.ReplaceAll(m.Sources.CityURL, "{month}", month.Format("2006-01"))
		tmp, err := m.download(ctx, url, m.cityPath())
		if err != nil {
			lastErr = err
			continue
		}
		f, err := os.Open(tmp)
		if err != nil {
			return err
		}
		t, err := ReadCity(f, m.Sources.RegionCountries)
		f.Close()
		if err != nil {
			os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, m.cityPath()); err != nil {
			return err
		}
		m.DB.SetCity(t)
		if m.OnCity != nil {
			m.OnCity()
		}
		return nil
	}
	return lastErr
}

// download fetches url beside dest (dest + ".part") and returns that path.
func (m *Manager) download(ctx context.Context, url, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "nx-insight")
	hc := m.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Minute}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	tmp := dest + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxDownload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxDownload {
		err = fmt.Errorf("%s: larger than %d bytes", url, maxDownload)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}
