package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

// When passes run (event-driven beyond the daily pass).
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
	// Tunnels is the tunnels as last polled (internal/tunnels), nil for
	// none.
	Tunnels func() []tunnels.View

	running sync.Mutex
	mu      sync.Mutex
	fails   int
	until   time.Time
	// breakerLoaded is whether fails and until were read from the database.
	breakerLoaded bool
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
	now := r.now()
	tx := r.DB.WithContext(ctx)
	// Whether or not it is on: turned off, the reports it left still age out.
	if err := tx.Where("at < ?", now.AddDate(0, 0, -ReportDays).Unix()).Delete(&Report{}).Error; err != nil {
		return err
	}
	s, err := Load(ctx, r.DB)
	if err != nil || !s.Enabled {
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
	if len(alerts) == 0 {
		return false, nil
	}
	for _, a := range alerts {
		if a.Kind == detect.KindProbed {
			return true, nil
		}
	}
	// The country's networks once, not once per alert.
	var seen []uint32
	if err := tx.Model(&model.PathHour{}).Where("country = ? AND hour >= ?", country, r.now().Add(-Window).Unix()).
		Distinct().Pluck("client_asn", &seen).Error; err != nil {
		return false, err
	}
	here := make(map[uint32]bool, len(seen))
	for _, a := range seen {
		here[a] = true
	}
	for _, a := range alerts {
		if here[a.ASN] {
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
	r.loadBreaker(ctx)
	r.mu.Lock()
	held := trigger != TriggerManual && now.Before(r.until)
	r.mu.Unlock()
	if held {
		return rep, nil
	}
	var tun []tunnels.View
	if r.Tunnels != nil {
		tun = r.Tunnels()
	}
	t, err := Build(ctx, r.DB, r.State, r.Org, country, now, tun)
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
		var n int64
		day := now.UTC().Truncate(24 * time.Hour).Unix()
		// One budget report a day per country is enough to say why — but a
		// pass the admin asked for always gets its answer.
		if trigger != TriggerManual {
			if err := r.DB.WithContext(ctx).Model(&Report{}).Where("country = ? AND status = ? AND at >= ?", country, StatusBudget, day).Count(&n).Error; err != nil || n > 0 {
				return rep, err
			}
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
	state := fmt.Sprintf("%d %d", r.fails, r.until.Unix())
	r.mu.Unlock()
	// Kept across a restart: a service that crashes and comes back every
	// minute must not call a failing provider every minute.
	if err := model.PutState(r.DB.WithContext(ctx), stateBreaker, state); err != nil {
		log.Printf("ai: saving the breaker: %v", err)
	}
	return rep, r.store(ctx, &rep)
}

const stateBreaker = "ai_breaker"

// loadBreaker reads the breaker a previous run left, once.
func (r *Runner) loadBreaker(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.breakerLoaded {
		return
	}
	r.breakerLoaded = true
	var st model.State
	if err := r.DB.WithContext(ctx).Where("key = ?", stateBreaker).Limit(1).Find(&st).Error; err != nil || st.Value == "" {
		return
	}
	var fails int
	var until int64
	if _, err := fmt.Sscan(st.Value, &fails, &until); err == nil && until > 0 {
		r.fails, r.until = fails, time.Unix(until, 0)
	}
}

func (r *Runner) store(ctx context.Context, rep *Report) error {
	return r.DB.WithContext(ctx).Create(rep).Error
}
