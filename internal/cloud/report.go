package cloud

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Report is NX's regional report as published (the cloud's src/reports.ts),
// named by the time it was extracted.
type Report struct {
	V           int             `json:"v"`
	ExtractedAt int64           `json:"extracted_at"`
	Tier        string          `json:"tier"` // full | disruption
	Countries   []ReportCountry `json:"countries"`
}

// ReportCountry is one client country's findings.
type ReportCountry struct {
	CC           string    `json:"cc"`
	From         int64     `json:"from"`
	To           int64     `json:"to"`
	Contributors string    `json:"contributors"` // "5-9" or "10+"
	Findings     []Finding `json:"findings"`
}

// Finding is one coded finding; the admin web words each code in four
// languages.
type Finding struct {
	Code       string  `json:"code"`
	Severity   string  `json:"severity"`
	ASN        uint32  `json:"asn"`
	Org        string  `json:"org"`
	Strategy   string  `json:"strategy"`
	NodeASN    uint32  `json:"node_asn"`
	Confidence float64 `json:"confidence"`
}

// Held is the report Insight holds, and what the last check said.
type Held struct {
	Report    *Report `json:"report"`
	CheckedAt int64   `json:"checkedAt"`
	// Latest is the newest extraction the cloud named on the last check.
	Latest int64  `json:"latest"`
	Error  string `json:"error,omitempty"`
}

type stored struct {
	Payload   string `json:"payload"`
	Sig       string `json:"sig"`
	CheckedAt int64  `json:"checkedAt"`
	Latest    int64  `json:"latest"`
}

func (c *Cloud) held(ctx context.Context) (stored, *Report) {
	var s stored
	if raw := c.state(ctx, stateReport); raw != "" {
		_ = json.Unmarshal([]byte(raw), &s)
	}
	if s.Payload == "" {
		return s, nil
	}
	// Checked again on every read: the database is not trusted to hold
	// only what NX signed.
	r, err := c.verified(s.Payload, s.Sig)
	if err != nil {
		return s, nil
	}
	return s, r
}

func (c *Cloud) verified(payload, sig string) (*Report, error) {
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || !ed25519.Verify(c.feed(), append([]byte(ReportContext), payload...), raw) {
		return nil, errors.New("the report's signature does not verify")
	}
	var r Report
	if err := json.Unmarshal([]byte(payload), &r); err != nil || r.V != 1 {
		return nil, errors.New("the report is not a version 1 report")
	}
	return &r, nil
}

// Held is the report Insight holds, for the admin web.
func (c *Cloud) Held(ctx context.Context) Held {
	s, r := c.held(ctx)
	return Held{Report: r, CheckedAt: s.CheckedAt, Latest: s.Latest, Error: c.state(ctx, stateReportErr)}
}

// CheckReport asks the cloud for a report newer than the one held — the
// owner's rule: Insight sends the extraction time of its last report; the
// cloud sends a newer one or the signal that there is none. Without force,
// a check within ReportGap of the last is skipped (the admin opening the
// page again).
func (c *Cloud) CheckReport(ctx context.Context, force bool) error {
	if !c.On(ctx) {
		return nil
	}
	c.mu.Lock()
	if c.checking || (!force && c.now().Sub(c.lastCheck) < ReportGap) {
		c.mu.Unlock()
		return nil
	}
	c.checking, c.lastCheck = true, c.now()
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.checking = false
		c.mu.Unlock()
	}()
	err := c.checkReport(ctx)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	_ = c.put(ctx, stateReportErr, msg)
	return err
}

func (c *Cloud) checkReport(ctx context.Context) error {
	k, err := c.key(ctx)
	if err != nil {
		return err
	}
	s, r := c.held(ctx)
	var since int64
	if r != nil {
		since = r.ExtractedAt
	}
	body, _ := json.Marshal(map[string]int64{"since": since, "ts": c.now().Unix()})
	var answer struct {
		New         bool   `json:"new"`
		ExtractedAt int64  `json:"extracted_at"`
		Payload     string `json:"payload"`
		Sig         string `json:"sig"`
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.post(ctx, k, "/v1/report", body, ReportRequestContext, nil, &answer); err != nil {
		var se *sendError
		if errors.As(err, &se) && se.msg == "contribute_first" {
			return errors.New("the cloud sends reports to contributors: no batch of this install reached it in the last 72 hours")
		}
		return err
	}
	s.CheckedAt, s.Latest = c.now().Unix(), answer.ExtractedAt
	if answer.New {
		nr, err := c.verified(answer.Payload, answer.Sig)
		if err != nil {
			return err
		}
		if nr.ExtractedAt <= since {
			return fmt.Errorf("the cloud sent a report no newer than the one held (%d)", nr.ExtractedAt)
		}
		s.Payload, s.Sig = answer.Payload, answer.Sig
	}
	raw, _ := json.Marshal(s)
	return c.put(ctx, stateReport, string(raw))
}

// Status is Mode B as the admin web shows it.
type Status struct {
	On          bool     `json:"on"`
	URL         string   `json:"url"`
	Fingerprint string   `json:"fingerprint"`
	Registered  bool     `json:"registered"`
	Error       string   `json:"error,omitempty"`
	Pending     int64    `json:"pending"`
	Failed      int64    `json:"failed"`
	LastSent    *Outbox  `json:"lastSent"`
	Recent      []Outbox `json:"recent"`
}

// Status reads Mode B's state.
func (c *Cloud) Status(ctx context.Context) (Status, error) {
	st := Status{On: c.On(ctx), URL: c.url(), Error: c.state(ctx, stateError)}
	if s := c.state(ctx, stateKey); s != "" {
		if k, err := c.key(ctx); err == nil {
			pub := publicB64(k)
			st.Fingerprint = Fingerprint(pub)
			st.Registered = c.state(ctx, stateRegistered) == pub
		}
	}
	tx := c.DB.WithContext(ctx)
	if err := tx.Model(&Outbox{}).Where("sent_at = 0 AND next_at < ?", int64(1)<<62).Count(&st.Pending).Error; err != nil {
		return st, err
	}
	if err := tx.Model(&Outbox{}).Where("sent_at = 0 AND next_at >= ?", int64(1)<<62).Count(&st.Failed).Error; err != nil {
		return st, err
	}
	var last []Outbox
	if err := tx.Where("sent_at > 0").Order("hour DESC").Limit(1).Find(&last).Error; err != nil {
		return st, err
	}
	if len(last) == 1 {
		st.LastSent = &last[0]
	}
	if err := tx.Order("hour DESC").Limit(48).Find(&st.Recent).Error; err != nil {
		return st, err
	}
	return st, nil
}

// Sent is one batch as it went out (or will), decoded for the admin.
func (c *Cloud) Sent(ctx context.Context, hour int64) (*Batch, error) {
	var o Outbox
	if err := c.DB.WithContext(ctx).Where("hour = ?", hour).First(&o).Error; err != nil {
		return nil, err
	}
	return decode(o.Body)
}
