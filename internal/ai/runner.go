package ai

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"gorm.io/gorm"
)

// When passes run (§4.8: event-driven beyond the daily pass).
const (
	// DailyEvery is the regular pass per client country.
	DailyEvery = 24 * time.Hour
	// AnomalyGap is the least time between two passes for one country that
	// an alert triggers.
	AnomalyGap = time.Hour
	// ReportDays is how long reports are kept.
	ReportDays = 90
	// breakerBase and breakerMax pace calls after failures: 15 minutes,
	// doubling up to six hours.
	breakerBase = 15 * time.Minute
	breakerMax  = 6 * time.Hour
)

// Triggers and statuses of a report.
const (
	TriggerDaily   = "daily"
	TriggerAnomaly = "anomaly"
	TriggerManual  = "manual"

	StatusOK     = "ok"
	StatusError  = "error"
	StatusBudget = "budget"
	StatusEmpty  = "empty"
)

// Report is one pass for one client country.
type Report struct {
	ID      uint   `json:"id" gorm:"primaryKey"`
	Country string `json:"country" gorm:"size:2;not null;index"`
	Trigger string `json:"trigger" gorm:"size:16;not null"`
	At      int64  `json:"at" gorm:"not null;index"`
	Model   string `json:"model"`
	Tokens  int    `json:"tokens"`
	Status  string `json:"status" gorm:"size:16;not null"`
	Error   string `json:"error"`
	// Rows is how many paths were sent, Dropped how many findings named
	// something the table did not hold.
	Rows    int `json:"rows"`
	Dropped int `json:"dropped"`
	// Findings is the kept findings, as JSON.
	Findings string `json:"findings"`
}

func (Report) TableName() string { return "ai_reports" }

// Tables are this package's, for the migration.
func Tables() []any { return []any{&Report{}} }

// Runner decides when to pass and runs one pass at a time.
type Runner struct {
	DB        *gorm.DB
	State     State
	Org       func(uint32) string
	Countries []string
	Client    *Client
	Now       func() time.Time

	running sync.Mutex
	mu      sync.Mutex
	fails   int
	until   time.Time
}

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Running reports whether a pass is under way.
func (r *Runner) Running() bool {
	if r.running.TryLock() {
		r.running.Unlock()
		return false
	}
	return true
}

// UsedToday is the tokens spent since 00:00 UTC.
func (r *Runner) UsedToday(ctx context.Context) (int, error) {
	day := r.now().UTC().Truncate(24 * time.Hour).Unix()
	var used int64
	err := r.DB.WithContext(ctx).Model(&Report{}).Where("at >= ?", day).Select("COALESCE(SUM(tokens), 0)").Scan(&used).Error
	return int(used), err
}

// Tick starts, in the background, the passes that are due: a country's
// daily one, or one an alert there triggered. It returns at once; a tick
// while a pass runs does nothing.
func (r *Runner) Tick(ctx context.Context) {
	if !r.running.TryLock() {
		return
	}
	go func() {
		defer r.running.Unlock()
		if err := r.due(ctx); err != nil {
			log.Printf("ai: %v", err)
		}
	}()
}

// RunNow starts a pass for country at once, whatever is due; false when one
// is already running.
func (r *Runner) RunNow(ctx context.Context, country string) bool {
	if !r.running.TryLock() {
		return false
	}
	go func() {
		defer r.running.Unlock()
		if _, err := r.pass(ctx, country, TriggerManual); err != nil {
			log.Printf("ai: %v", err)
		}
	}()
	return true
}

func (r *Runner) due(ctx context.Context) error {
	s, err := Load(ctx, r.DB)
	if err != nil || !s.Enabled {
		return err
	}
	now := r.now()
	tx := r.DB.WithContext(ctx)
	if err := tx.Where("at < ?", now.AddDate(0, 0, -ReportDays).Unix()).Delete(&Report{}).Error; err != nil {
		return err
	}
	for _, country := range r.Countries {
		var last []Report
		if err := tx.Where("country = ? AND status IN ?", country, []string{StatusOK, StatusEmpty}).Order("at DESC").Limit(1).Find(&last).Error; err != nil {
			return err
		}
		var lastAt int64
		if len(last) == 1 {
			lastAt = last[0].At
		}
		trigger := ""
		switch {
		case now.Unix()-lastAt >= int64(DailyEvery/time.Second):
			trigger = TriggerDaily
		case now.Unix()-lastAt >= int64(AnomalyGap/time.Second):
			fresh, err := r.alertedSince(ctx, country, lastAt)
			if err != nil {
				return err
			}
			if fresh {
				trigger = TriggerAnomaly
			}
		}
		if trigger == "" {
			continue
		}
		if _, err := r.pass(ctx, country, trigger); err != nil {
			return err
		}
	}
	return nil
}

// alertedSince reports whether a path or outage alert for a network seen in
// country, or a probed alert, came after since.
func (r *Runner) alertedSince(ctx context.Context, country string, since int64) (bool, error) {
	tx := r.DB.WithContext(ctx)
	var alerts []detect.Alert
	if err := tx.Where("at > ? AND kind IN ?", since,
		[]string{detect.KindDegraded, detect.KindOutage, detect.KindProbed}).Find(&alerts).Error; err != nil {
		return false, err
	}
	for _, a := range alerts {
		if a.Kind == detect.KindProbed {
			return true, nil
		}
		var n int64
		if err := tx.Model(&model.PathHour{}).Where("client_asn = ? AND country = ? AND hour >= ?",
			a.ASN, country, r.now().Add(-Window).Unix()).Count(&n).Error; err != nil {
			return false, err
		}
		if n > 0 {
			return true, nil
		}
	}
	return false, nil
}

// ErrBreaker is a pass held back after recent failures.
var ErrBreaker = errors.New("held back after recent failures")

// pass runs one pass and stores its report. A provider's failure is a
// report with status error, not an error of pass.
func (r *Runner) pass(ctx context.Context, country, trigger string) (Report, error) {
	now := r.now()
	rep := Report{Country: country, Trigger: trigger, At: now.Unix(), Findings: "[]"}
	s, err := Load(ctx, r.DB)
	if err != nil {
		return rep, err
	}
	if !s.Enabled {
		return rep, nil
	}
	rep.Model = s.Model
	r.mu.Lock()
	held := trigger != TriggerManual && now.Before(r.until)
	r.mu.Unlock()
	if held {
		return rep, nil
	}
	t, err := Build(ctx, r.DB, r.State, r.Org, country, now)
	if err != nil {
		return rep, err
	}
	rep.Rows = len(t.Paths)
	if len(t.Paths) == 0 {
		rep.Status = StatusEmpty
		return rep, r.store(ctx, &rep)
	}
	user := t.Text()
	used, err := r.UsedToday(ctx)
	if err != nil {
		return rep, err
	}
	if used+(len(systemPrompt)+len(user))/4 > s.DailyTokens {
		// One budget report a day per country is enough to say why.
		var n int64
		day := now.UTC().Truncate(24 * time.Hour).Unix()
		if err := r.DB.WithContext(ctx).Model(&Report{}).Where("country = ? AND status = ? AND at >= ?", country, StatusBudget, day).Count(&n).Error; err != nil || n > 0 {
			return rep, err
		}
		rep.Status = StatusBudget
		return rep, r.store(ctx, &rep)
	}
	client := r.Client
	if client == nil {
		client = &Client{}
	}
	a, err := client.Complete(ctx, s, user)
	rep.Tokens = a.Tokens
	if err == nil {
		var found []Finding
		found, rep.Dropped, err = Parse(a.Content, t)
		if err == nil {
			if found == nil {
				found = []Finding{}
			}
			raw, _ := json.Marshal(found)
			rep.Status, rep.Findings = StatusOK, string(raw)
		}
	}
	r.mu.Lock()
	if err != nil {
		rep.Status, rep.Error = StatusError, err.Error()
		backoff := breakerBase << min(r.fails, 5)
		r.fails++
		r.until = now.Add(min(backoff, breakerMax))
	} else {
		r.fails, r.until = 0, time.Time{}
	}
	r.mu.Unlock()
	return rep, r.store(ctx, &rep)
}

func (r *Runner) store(ctx context.Context, rep *Report) error {
	return r.DB.WithContext(ctx).Create(rep).Error
}
