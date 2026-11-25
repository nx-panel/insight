// Package cloud is NX Insight's Mode B: with the admin's consent, the
// hour just closed goes to NX's cloud as anonymous cells (batch.go), signed
// with this install's contributor key, and the regional report NX publishes
// comes back.
//
// The key is registered with the panel (PUT /api/telemetry/contributor-key,
// with a proof that this install holds it); the panel hands it to the
// licence service, which tells the cloud whether a licence stands behind
// it. Turning Mode B off removes it from the panel and drops whatever was
// waiting to be sent: a batch already being posted when off is pressed
// still lands, nothing else does.
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

// The contexts every signature covers first: the same strings the cloud
// checks a batch or a report request against, and the panel a key's proof.
const (
	BatchContext         = "nx-insight-batch-v1:"
	ReportRequestContext = "nx-insight-report-request-v1:"
	ReportContext        = "nx-insight-report-v1:"
	ProofContext         = "nx-contributor-key-v1:"
)

// FeedKey is the public half of NX's feed key: every report is
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

// unconfirmed is cloud_registered for a key the panel may hold but has not
// confirmed under the consent in force: an off still removes it, an on puts
// it again.
const unconfirmed = "unconfirmed"

// neverRetry is the next_at of a batch the cloud refused for good: far
// enough ahead that no send looks at it again. Status reports such a batch
// as Refused.
const neverRetry = int64(1) << 62

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
	// Panel is the client to register the key with; it returns nil until
	// Insight has panel credentials.
	Panel func() Panel
	// HTTP is the client for the cloud; nil is a 30-second one.
	HTTP *http.Client
	Now  func() time.Time

	mu        sync.Mutex
	lastCheck time.Time
	checking  bool
	feedKey   ed25519.PublicKey
	kick      chan struct{}
	// ops serialises the switch and the panel calls (lock, unlock): a Put
	// of the key must not land after the Delete that turning Mode B off
	// made. A one-slot channel, so a waiter can give up with its context.
	ops chan struct{}
}

// lock takes ops, or returns ctx's error when ctx ends first.
func (c *Cloud) lock(ctx context.Context) error {
	c.mu.Lock()
	if c.ops == nil {
		c.ops = make(chan struct{}, 1)
	}
	ops := c.ops
	c.mu.Unlock()
	select {
	case ops <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Cloud) unlock() { <-c.ops }

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

// On reports whether the admin turned Mode B on. cloud_on holds the
// consent's id, "" while off: each on writes a new one, so work begun under
// an earlier consent can tell it is no longer in force.
func (c *Cloud) On(ctx context.Context) bool { return c.state(ctx, stateOn) != "" }

// errNoPanel is a panel call before Insight has panel credentials.
var errNoPanel = errors.New("Insight has no panel credentials yet")

// errDamaged is a stored seed that does not decode.
var errDamaged = errors.New("the stored contributor key is damaged: turning Mode B off and on again makes a new one")

func seedOf(s string) ([]byte, error) {
	seed, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errDamaged
	}
	return seed, nil
}

// key reads this install's key, making one the first time. A stored seed
// that does not decode is an error, never a silent new key: the panel and
// the cloud know the old one. Only turning Mode B off drops it.
func (c *Cloud) key(ctx context.Context) (ed25519.PrivateKey, error) {
	if s := c.state(ctx, stateKey); s != "" {
		seed, err := seedOf(s)
		if err != nil {
			return nil, err
		}
		return ed25519.NewKeyFromSeed(seed), nil
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
// with the panel; off drops every batch not sent yet (and a damaged key)
// and removes the key from the panel, retried by Tick until the panel
// takes it.
func (c *Cloud) SetOn(ctx context.Context, on bool) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if !on {
		seed := c.state(ctx, stateKey)
		_, damaged := seedOf(seed)
		err := c.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, k := range []string{stateOn, stateBuilt} {
				if err := model.PutState(tx, k, ""); err != nil {
					return err
				}
			}
			// The admin's way out of a damaged key: on again makes a new one.
			if seed != "" && damaged != nil {
				if err := tx.Where("key = ?", stateKey).Delete(&model.State{}).Error; err != nil {
					return err
				}
			}
			return tx.Where("sent_at = 0").Delete(&Outbox{}).Error
		})
		if err != nil {
			return err
		}
		return c.unregisterLocked(ctx)
	}
	if _, err := c.key(ctx); err != nil {
		return err
	}
	// Already on: the hours waiting for their build keep waiting.
	if !c.On(ctx) {
		// A new consent: the first hour sent is the hour in progress at the
		// moment of consent, which includes minutes before the switch was
		// turned on; nothing older goes out. One transaction, so on never
		// stands without its mark. The error of before is gone with the off,
		// and the key is put again: the panel may have carried out a Delete
		// whose answer was lost.
		now := c.now()
		err := c.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			if err := model.PutState(tx, stateOn, rand.Text()); err != nil {
				return err
			}
			if err := model.PutState(tx, stateBuilt, strconv.FormatInt(hourOf(now)-3600, 10)); err != nil {
				return err
			}
			if err := model.PutState(tx, stateError, ""); err != nil {
				return err
			}
			var reg model.State
			if err := tx.Where("key = ?", stateRegistered).Limit(1).Find(&reg).Error; err != nil {
				return err
			}
			if reg.Value == "" {
				return nil
			}
			return model.PutState(tx, stateRegistered, unconfirmed)
		})
		if err != nil {
			return err
		}
	}
	err := c.registerLocked(ctx)
	c.Kick()
	return err
}

// unregisterLocked removes the key from the panel, under ops. The key
// counts as registered until the panel took the Delete; the error waits in
// Status.
func (c *Cloud) unregisterLocked(ctx context.Context) error {
	if c.state(ctx, stateRegistered) == "" {
		// Nothing to remove: an error left from when Mode B was on (no panel
		// credentials, a refused Put) no longer applies.
		return c.put(ctx, stateError, "")
	}
	p := c.panel()
	if p == nil {
		_ = c.put(ctx, stateError, errNoPanel.Error())
		return errNoPanel
	}
	if err := p.Delete(ctx, "/telemetry/contributor-key"); err != nil && !notFound(err) {
		err = fmt.Errorf("the panel did not remove the key: %w", err)
		_ = c.put(ctx, stateError, err.Error())
		return err
	}
	_ = c.put(ctx, stateError, "")
	return c.put(ctx, stateRegistered, "")
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

// register puts the key and its proof with the panel, once per consent and
// again on each Tick until the panel confirms it; under ops, and only while
// Mode B is still on.
func (c *Cloud) register(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if !c.On(ctx) {
		return nil
	}
	return c.registerLocked(ctx)
}

// unregister retries the Delete an off left undone, under ops.
func (c *Cloud) unregister(ctx context.Context) error {
	if err := c.lock(ctx); err != nil {
		return err
	}
	defer c.unlock()
	if c.On(ctx) {
		return nil
	}
	return c.unregisterLocked(ctx)
}

func (c *Cloud) registerLocked(ctx context.Context) error {
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
		return errNoPanel
	}
	// From here the panel may hold the key whatever its answer says: an off
	// removes it even when the answer to this Put is lost.
	if err := c.put(ctx, stateRegistered, unconfirmed); err != nil {
		return err
	}
	proof := base64.StdEncoding.EncodeToString(ed25519.Sign(k, []byte(ProofContext+pub)))
	if err := p.Put(ctx, "/telemetry/contributor-key", map[string]string{"public_key": pub, "proof": proof}, nil); err != nil {
		return fmt.Errorf("the panel did not take the key: %w", err)
	}
	_ = c.put(ctx, stateError, "")
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
			// The report check Insight makes once, when it starts.
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
		// A key the panel did not take off when Mode B was turned off.
		if c.state(ctx, stateRegistered) != "" {
			_ = c.unregister(ctx) // the error waits in Status
		}
		return nil
	}
	if err := c.register(ctx); err != nil {
		_ = c.put(ctx, stateError, err.Error())
		return nil // the batches wait in the outbox
	}
	// Not before the sources are ready: built against empty shapes and an
	// empty detector, an hour would come out with no cells, or wrong ones.
	// The batches already built still go out.
	if c.Sources.Ready == nil || c.Sources.Ready() {
		if err := c.build(ctx, now); err != nil {
			return err
		}
	}
	return c.send(ctx, now)
}

// build makes the batches of the hours closed since the last one built.
// An hour with rows that gave no cells because no shape is known yet is
// not passed: it is built once the shapes are in.
func (c *Cloud) build(ctx context.Context, now time.Time) error {
	consent := c.state(ctx, stateOn)
	if consent == "" {
		return nil
	}
	closed := hourOf(now) - 3600
	built := c.state(ctx, stateBuilt)
	if built == "" {
		// On with no mark: as SetOn does, the first hour sent is the hour in
		// progress at the moment of consent, which includes minutes before
		// the switch was turned on — never Keep ago: no older hour is known
		// to be consented.
		_, err := c.advance(ctx, consent, built, closed, nil, -1)
		return err
	}
	last, _ := strconv.ParseInt(built, 10, 64)
	// The ingest writes every five minutes: an hour is built once its next
	// flush is surely in.
	if now.Unix()%3600 < 6*60 {
		closed -= 3600
	}
	from := max(last+3600, oldestBuilt(now))
	for h := from; h <= closed; h += 3600 {
		// The hour's marks counted first: one recorded after this is caught
		// by advance, and the hour built again.
		marked, err := countMarks(c.DB.WithContext(ctx), h)
		if err != nil {
			return err
		}
		b, rows, err := build(ctx, c.Sources, h)
		if err != nil {
			return err
		}
		// No shape known yet: wait. Known limit: such an hour is read again
		// on every tick until the shapes return or it is older than Keep. Its
		// verdicts are its own hour's (Mark), however late it is built.
		if len(b.Cells) == 0 && rows > 0 && (c.Sources.Shapes == nil || len(c.Sources.Shapes()) == 0) {
			return nil
		}
		var row *Outbox
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
			row = &Outbox{Hour: h, Body: gz.Bytes(), Cells: len(b.Cells), CreatedAt: now.Unix()}
		}
		moved, err := c.advance(ctx, consent, built, h, row, marked)
		if err != nil || !moved {
			return err
		}
		built = strconv.FormatInt(h, 10)
	}
	return nil
}

// advance queues row (nil: none) and moves cloud_built_through from from
// to h, in one transaction that holds cloud_on locked, and only while the
// consent the build began under is in force, cloud_built_through is still
// from, h is not older than Keep now, and h holds the marks the build
// counted (marked; -1: not counted). Anything else means an off, an on,
// another build, a Mark or the hour's turn came between: it reports false
// and the build stops, to build h again next time (or skip it, too old).
// An off after it drops the row.
func (c *Cloud) advance(ctx context.Context, consent, from string, h int64, row *Outbox, marked int64) (bool, error) {
	moved := false
	err := c.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var on, mark model.State
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).Where("key = ?", stateOn).Limit(1).Find(&on).Error; err != nil {
			return err
		}
		if err := tx.Where("key = ?", stateBuilt).Limit(1).Find(&mark).Error; err != nil {
			return err
		}
		if on.Value != consent || mark.Value != from {
			return nil
		}
		if marked >= 0 {
			if h < oldestBuilt(c.now()) {
				return nil // a Mark since may have dropped its records
			}
			n, err := countMarks(tx, h)
			if err != nil {
				return err
			}
			if n != marked {
				return nil
			}
		}
		if row != nil {
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(row).Error; err != nil {
				return err
			}
		}
		moved = true
		return model.PutState(tx, stateBuilt, strconv.FormatInt(h, 10))
	})
	return moved && err == nil, err
}

// sendError is a refusal the cloud gave; permanent ones are not retried.
type sendError struct {
	status    int
	msg       string
	permanent bool
}

func (e *sendError) Error() string { return fmt.Sprintf("the cloud answered %d: %s", e.status, e.msg) }

func (c *Cloud) send(ctx context.Context, now time.Time) error {
	consent := c.state(ctx, stateOn)
	if consent == "" {
		return nil
	}
	var due []int64
	if err := c.DB.WithContext(ctx).Model(&Outbox{}).Where("sent_at = 0 AND next_at <= ?", now.Unix()).Order("hour").Limit(24).Pluck("hour", &due).Error; err != nil {
		return err
	}
	k, err := c.key(ctx)
	if err != nil {
		return err
	}
	for _, h := range due {
		// Each batch is read again right before its post, and goes only
		// while the consent the send began under is in force: an off since
		// dropped it, and an on after that is a consent of its own. A post
		// already on its way when off is pressed still lands.
		if c.state(ctx, stateOn) != consent {
			return nil
		}
		var rows []Outbox
		if err := c.DB.WithContext(ctx).Where("hour = ? AND sent_at = 0", h).Limit(1).Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			continue
		}
		o := rows[0]
		err := c.post(ctx, k, "/v1/batch", o.Body, BatchContext, map[string]string{"Content-Encoding": "gzip"}, nil)
		upd := map[string]any{"attempts": o.Attempts + 1}
		var se *sendError
		switch {
		case err == nil:
			upd["sent_at"], upd["last_error"] = now.Unix(), ""
			c.errorUnder(ctx, consent, "")
		case errors.As(err, &se) && se.permanent:
			// The cloud will never take this batch: kept unsent, never retried.
			upd["next_at"], upd["last_error"] = neverRetry, err.Error()
			c.errorUnder(ctx, consent, err.Error())
		default:
			// Doubling from five minutes to two hours; a key the licence
			// service does not know yet is the common case for a while.
			wait := min(5*time.Minute<<min(o.Attempts, 5), 2*time.Hour)
			upd["next_at"], upd["last_error"] = now.Add(wait).Unix(), err.Error()
			c.errorUnder(ctx, consent, err.Error())
		}
		if err := c.DB.WithContext(ctx).Model(&Outbox{}).Where("hour = ?", o.Hour).Updates(upd).Error; err != nil {
			return err
		}
	}
	return nil
}

// errorUnder writes cloud_error only while consent is still the one in
// force, checked and written in one transaction that holds cloud_on locked:
// an off since the send began wrote its own (a failed Delete's reason), and
// a post that finishes after it does not overwrite it.
func (c *Cloud) errorUnder(ctx context.Context, consent, msg string) {
	_ = c.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var on model.State
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).Where("key = ?", stateOn).Limit(1).Find(&on).Error; err != nil {
			return err
		}
		if on.Value != consent {
			return nil
		}
		return model.PutState(tx, stateError, msg)
	})
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
		// check; 410 an hour sent too many times — none gets better by
		// sending it again. 403 is a key the licence service does not know
		// yet, 425 an hour the cloud does not hold closed yet, 429 and 5xx
		// are the cloud's: all retried with the back-off.
		perm := res.StatusCode == http.StatusBadRequest || res.StatusCode == http.StatusRequestEntityTooLarge ||
			res.StatusCode == http.StatusUnsupportedMediaType || res.StatusCode == http.StatusUnauthorized ||
			res.StatusCode == http.StatusGone
		return &sendError{status: res.StatusCode, msg: e.Error, permanent: perm}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
