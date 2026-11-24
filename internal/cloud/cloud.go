// Package cloud is NX Insight's Mode B (nx-panel docs/path-telemetry.md
// §4.4, §5.3, PT19): with the admin's consent, the hour just closed goes to
// NX's cloud as anonymous cells (batch.go), signed with this install's
// contributor key, and the regional report NX publishes comes back.
//
// The key is registered with the panel (PUT /api/telemetry/contributor-key,
// with a proof that this install holds it); the panel hands it to the
// licence service, which tells the cloud whether a licence stands behind
// it. Turning Mode B off removes it from the panel and drops whatever was
// waiting to be sent: nothing leaves after the admin said no.
package cloud

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/model"
)

// The contexts every signature covers first (the cloud's src/sign.ts and
// the panel's license.ContributorProofContext).
const (
	BatchContext         = "nx-insight-batch-v1:"
	ReportRequestContext = "nx-insight-report-request-v1:"
	ReportContext        = "nx-insight-report-v1:"
	ProofContext         = "nx-contributor-key-v1:"
)

// FeedKey is the public half of NX's feed key (P41 a): every report is
// signed with it, and one that does not verify is not shown.
const FeedKey = "w/Qx7QJ285cVegS9m18SNo1jx8i3RGY2EKaoL46nXEk="

// DefaultURL is NX's cloud.
const DefaultURL = "https://insight.nx-panel.org"

const (
	// SendEvery is how often the outbox is looked at.
	SendEvery = 5 * time.Minute
	// Keep is how long a batch waits to be sent, and how long a sent one
	// stays for the admin to read.
	Keep = 48 * time.Hour
	// ReportGap is the least time between two report checks the admin's
	// opening of the page makes.
	ReportGap = 10 * time.Minute
)

// State keys.
const (
	stateOn         = "cloud_on"
	stateKey        = "cloud_key"
	stateRegistered = "cloud_registered"
	stateBuilt      = "cloud_built_through"
	stateReport     = "cloud_report"
	stateError      = "cloud_error"
	stateReportErr  = "cloud_report_error"
)

// Outbox is one hour's batch, waiting or sent (model.CloudOutbox).
type Outbox = model.CloudOutbox

// Panel is the part of the panel client Mode B uses.
type Panel interface {
	Put(ctx context.Context, path string, body any, out any) error
	Delete(ctx context.Context, path string) error
}

// Cloud is Mode B: the key, the outbox, the report.
type Cloud struct {
	DB      *gorm.DB
	Sources Sources
	// URL is the cloud's address; "" is DefaultURL.
	URL string
	// Panel is the client to register the key with, nil while unregistered.
	Panel func() Panel
	// HTTP is the client for the cloud; nil is a 30-second one.
	HTTP *http.Client
	Now  func() time.Time

	mu        sync.Mutex
	lastCheck time.Time
	checking  bool
	feedKey   ed25519.PublicKey
	kick      chan struct{}
}

func (c *Cloud) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cloud) url() string {
	if c.URL != "" {
		return strings.TrimRight(c.URL, "/")
	}
	return DefaultURL
}

func (c *Cloud) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Cloud) feed() ed25519.PublicKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.feedKey == nil {
		k, _ := base64.StdEncoding.DecodeString(FeedKey)
		c.feedKey = ed25519.PublicKey(k)
	}
	return c.feedKey
}

// SetFeedKey replaces NX's public key, for tests and a local cloud.
func (c *Cloud) SetFeedKey(k ed25519.PublicKey) {
	c.mu.Lock()
	c.feedKey = k
	c.mu.Unlock()
}

func (c *Cloud) state(ctx context.Context, key string) string {
	var st model.State
	if c.DB.WithContext(ctx).Where("key = ?", key).Limit(1).Find(&st).Error != nil {
		return ""
	}
	return st.Value
}

func (c *Cloud) put(ctx context.Context, key, value string) error {
	return model.PutState(c.DB.WithContext(ctx), key, value)
}

// On reports whether the admin turned Mode B on.
func (c *Cloud) On(ctx context.Context) bool { return c.state(ctx, stateOn) == "on" }

// key reads this install's key, making one the first time.
func (c *Cloud) key(ctx context.Context) (ed25519.PrivateKey, error) {
	if s := c.state(ctx, stateKey); s != "" {
		seed, err := base64.StdEncoding.DecodeString(s)
		if err == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := c.put(ctx, stateKey, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		return nil, err
	}
	return priv, nil
}

func publicB64(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// Fingerprint is eight bytes of the public key's SHA-256, as the panel's
// licence page shows it.
func Fingerprint(pub string) string {
	sum := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(sum[:8])
}

// SetOn turns Mode B on or off. On makes the key (once) and registers it
// with the panel; off removes it from the panel and drops every batch not
// sent yet.
func (c *Cloud) SetOn(ctx context.Context, on bool) error {
	if !on {
		if err := c.put(ctx, stateOn, ""); err != nil {
			return err
		}
		if err := c.DB.WithContext(ctx).Where("sent_at = 0").Delete(&Outbox{}).Error; err != nil {
			return err
		}
		var err error
		if p := c.panel(); p != nil {
			if err = p.Delete(ctx, "/telemetry/contributor-key"); err != nil && !notFound(err) {
				err = fmt.Errorf("the panel did not remove the key: %w", err)
			} else {
				err = nil
			}
		}
		_ = c.put(ctx, stateRegistered, "")
		return err
	}
	if _, err := c.key(ctx); err != nil {
		return err
	}
	if err := c.put(ctx, stateOn, "on"); err != nil {
		return err
	}
	// Build from the hour that is closing now: nothing older than the
	// consent goes out.
	now := c.now().Unix()
	if err := c.put(ctx, stateBuilt, strconv.FormatInt(now-now%3600-3600, 10)); err != nil {
		return err
	}
	err := c.register(ctx)
	c.Kick()
	return err
}

func (c *Cloud) panel() Panel {
	if c.Panel == nil {
		return nil
	}
	return c.Panel()
}

func notFound(err error) bool {
	var pe *panel.Error
	return errors.As(err, &pe) && pe.Status == http.StatusNotFound
}

// register puts the key and its proof with the panel, once per key.
func (c *Cloud) register(ctx context.Context) error {
	k, err := c.key(ctx)
	if err != nil {
		return err
	}
	pub := publicB64(k)
	if c.state(ctx, stateRegistered) == pub {
		return nil
	}
	p := c.panel()
	if p == nil {
		return errors.New("not registered with a panel yet")
	}
	proof := base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte(ProofContext+pub)))
	if err := p.Put(ctx, "/telemetry/contributor-key", map[string]string{"public_key": pub, "proof": proof}, nil); err != nil {
		return fmt.Errorf("the panel did not take the key: %w", err)
	}
	return c.put(ctx, stateRegistered, pub)
}

// Kick asks the loop to look at the outbox now.
func (c *Cloud) Kick() {
	c.mu.Lock()
	if c.kick == nil {
		c.kick = make(chan struct{}, 1)
	}
	k := c.kick
	c.mu.Unlock()
	select {
	case k <- struct{}{}:
	default:
	}
}

// Run is the loop: build the closed hours, send what is due, prune. A
// report check runs once at start.
func (c *Cloud) Run(ctx context.Context) {
	c.Kick()
	c.mu.Lock()
	kick := c.kick
	c.mu.Unlock()
	t := time.NewTicker(SendEvery)
	defer t.Stop()
	started := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
		if err := c.Tick(ctx); err != nil {
			log.Printf("cloud: %v", err)
		}
		if !started {
			started = true
			// "With opening": the report check Insight makes when it starts.
			go func() {
				if err := c.CheckReport(ctx, true); err != nil {
					log.Printf("cloud: report: %v", err)
				}
			}()
		}
	}
}

// Tick does one round of the loop.
func (c *Cloud) Tick(ctx context.Context) error {
	now := c.now()
	// Sent batches stay Keep for the admin to read; unsent ones are dropped
	// at Keep, and all of them when Mode B is off.
	cut := now.Add(-Keep).Unix()
	if err := c.DB.WithContext(ctx).Where("hour < ?", cut).Delete(&Outbox{}).Error; err != nil {
		return err
	}
	if !c.On(ctx) {
		return nil
	}
	if err := c.register(ctx); err != nil {
		_ = c.put(ctx, stateError, err.Error())
		return nil // the batches wait in the outbox
	}
	if err := c.build(ctx, now); err != nil {
		return err
	}
	return c.send(ctx, now)
}

// build makes the batches of the hours closed since the last one built.
func (c *Cloud) build(ctx context.Context, now time.Time) error {
	last, _ := strconv.ParseInt(c.state(ctx, stateBuilt), 10, 64)
	closed := now.Unix() - now.Unix()%3600 - 3600
	// The ingest writes every five minutes: an hour is built once its next
	// flush is surely in.
	if now.Unix()%3600 < 6*60 {
		closed -= 3600
	}
	from := max(last+3600, now.Add(-Keep).Unix()/3600*3600)
	for h := from; h <= closed; h += 3600 {
		b, err := Build(ctx, c.Sources, h)
		if err != nil {
			return err
		}
		if len(b.Cells) > 0 {
			raw, err := json.Marshal(b)
			if err != nil {
				return err
			}
			var gz bytes.Buffer
			w := gzip.NewWriter(&gz)
			_, _ = w.Write(raw)
			if err := w.Close(); err != nil {
				return err
			}
			row := Outbox{Hour: h, Body: gz.Bytes(), Cells: len(b.Cells), CreatedAt: now.Unix()}
			if err := c.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
		}
		if err := c.put(ctx, stateBuilt, strconv.FormatInt(h, 10)); err != nil {
			return err
		}
	}
	return nil
}

// sendError is a refusal the cloud gave; permanent ones are not retried.
type sendError struct {
	status    int
	msg       string
	permanent bool
}

func (e *sendError) Error() string { return fmt.Sprintf("the cloud answered %d: %s", e.status, e.msg) }

func (c *Cloud) send(ctx context.Context, now time.Time) error {
	var due []Outbox
	if err := c.DB.WithContext(ctx).Where("sent_at = 0 AND next_at <= ?", now.Unix()).Order("hour").Limit(24).Find(&due).Error; err != nil {
		return err
	}
	k, err := c.key(ctx)
	if err != nil {
		return err
	}
	for _, o := range due {
		err := c.post(ctx, k, "/v1/batch", o.Body, BatchContext, map[string]string{"Content-Encoding": "gzip"}, nil)
		upd := map[string]any{"attempts": o.Attempts + 1}
		var se *sendError
		switch {
		case err == nil:
			upd["sent_at"], upd["last_error"] = now.Unix(), ""
			_ = c.put(ctx, stateError, "")
		case errors.As(err, &se) && se.permanent:
			// The cloud will never take this batch: kept unsent, never retried.
			upd["next_at"], upd["last_error"] = int64(1)<<62, err.Error()
			_ = c.put(ctx, stateError, err.Error())
		default:
			// Doubling from five minutes to two hours; a key the licence
			// service does not know yet is the common case for a while.
			wait := min(5*time.Minute<<min(o.Attempts, 5), 2*time.Hour)
			upd["next_at"], upd["last_error"] = now.Add(wait).Unix(), err.Error()
			_ = c.put(ctx, stateError, err.Error())
		}
		if err := c.DB.WithContext(ctx).Model(&Outbox{}).Where("hour = ?", o.Hour).Updates(upd).Error; err != nil {
			return err
		}
	}
	return nil
}

// post signs body and POSTs it; out, when set, receives the JSON answer.
func (c *Cloud) post(ctx context.Context, k ed25519.PrivateKey, path string, body []byte, sigContext string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-NX-Key", publicB64(k))
	req.Header.Set("X-NX-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(k, append([]byte(sigContext), body...))))
	for h, v := range headers {
		req.Header.Set(h, v)
	}
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = http.StatusText(res.StatusCode)
		}
		// 400, 413 and 415 are this batch; 401 a signature the cloud cannot
		// check — none gets better by sending it again. 403 is a key the
		// licence service does not know yet, 429 and 5xx are the cloud's.
		perm := res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusRequestEntityTooLarge ||
			res.StatusCode == http.StatusUnsupportedMediaType || res.StatusCode == http.StatusUnauthorized
		return &sendError{status: res.StatusCode, msg: e.Error, permanent: perm}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
