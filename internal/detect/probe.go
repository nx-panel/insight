package detect

import (
	"context"
	"sort"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/model"
)

// Active probing. The node counts the signals and acts on none; here they become a suspicion
// score per endpoint, an endpoint.probed alert, and a suggestion to rotate
// the endpoint before the probing turns into a block. An endpoint is one
// node and inbound: on a node an inbound is one port and one SNI set, the
// "address × port × SNI class" as the telemetry sees it.
//
// The score is not calibrated yet. Each probed alert is kept with its time,
// so whether a path alert on the same endpoint followed within
// CalibrateWithin can be read back (EndpointView.Followed) and the weights
// set from data rather than from the literature.

const (
	// ScoreWindow is how far back the evidence is summed.
	ScoreWindow = 6 * time.Hour
	// replayPoints is each replayed handshake's weight, replayCap the most
	// replays may give: a replay is the strongest evidence of a prober
	// — a real client never sends one handshake twice.
	replayPoints = 20
	replayCap    = 80
	// followPoints is what a surge of follow-up failures adds: at least
	// followMin in the window and followSurge times the endpoint's own
	// normal for that long. On a busy inbound most failures follow some
	// success, so only a change against itself says anything.
	followPoints = 20
	followMin    = 10
	followSurge  = 3
	// followNormalHours is how much history the follow-up normal needs.
	followNormalHours = 24
	// ProbedAt is the score that raises endpoint.probed; the endpoint is
	// quiet again below QuietBelow (hysteresis), and may alert again after.
	ProbedAt   = 40
	QuietBelow = 20
	// CalibrateWithin is how soon after a probed alert a path alert on the
	// same endpoint counts as having followed it.
	CalibrateWithin = 48 * time.Hour
)

// KindProbed is an endpoint whose suspicion score reached ProbedAt.
const KindProbed = "endpoint.probed"

// Suspicion is one endpoint's score and the evidence behind it, over the
// last ScoreWindow.
type Suspicion struct {
	NodeID  uint   `json:"nodeId" gorm:"primaryKey;autoIncrement:false"`
	Inbound string `json:"inbound" gorm:"primaryKey;size:128"`
	Score   int    `json:"score"`
	// The window's evidence.
	Replayed     uint64 `json:"replayed"`
	FollowUpFail uint64 `json:"followUpFail"`
	// FollowNormal is the endpoint's follow-up failures per ScoreWindow over
	// the week before the window.
	FollowNormal float64 `json:"followNormal"`
	NoRoute      uint64  `json:"noRoute"`
	QUICStray    uint64  `json:"quicStray" gorm:"column:quic_stray"`
	Failed       uint64  `json:"failed"`
	Accepted     uint64  `json:"accepted"`
	// Probed is whether the endpoint is in a probed episode now, ProbedAt
	// when its last episode began, LastEvidence the newest hour that held a
	// replay.
	Probed       bool  `json:"probed"`
	ProbedAtUnix int64 `json:"probedAt" gorm:"column:probed_at"`
	LastEvidence int64 `json:"lastEvidence"`
	UpdatedAt    int64 `json:"updatedAt"`
}

func (Suspicion) TableName() string { return "endpoint_suspicion" }

type evidenceRow struct {
	NodeID       uint
	Inbound      string
	Replayed     uint64
	FollowUpFail uint64
	NoRoute      uint64
	QUICStray    uint64 `gorm:"column:quic_stray"`
	Failed       uint64
	Accepted     uint64
	LastEvidence int64
	FirstHour    int64
}

func (d *Detector) evidence(tx *gorm.DB, from, to int64) (map[Endpoint]evidenceRow, error) {
	var rows []evidenceRow
	err := tx.Model(&model.PathHour{}).
		Select("node_id, inbound, SUM(replayed) AS replayed, SUM(follow_up_fail) AS follow_up_fail, "+
			"SUM(failed_no_route) AS no_route, SUM(failed_quic) AS quic_stray, "+
			"SUM(failed_tls + failed_auth + failed_timeout + failed_reset + failed_eof + failed_other) AS failed, "+
			"SUM(accepted) AS accepted, MAX(CASE WHEN replayed > 0 THEN hour ELSE 0 END) AS last_evidence, MIN(hour) AS first_hour").
		Where("hour >= ? AND hour < ?", from, to).Group("node_id, inbound").Scan(&rows).Error
	out := make(map[Endpoint]evidenceRow, len(rows))
	for _, r := range rows {
		out[Endpoint{r.NodeID, r.Inbound}] = r
	}
	return out, err
}

// Endpoint is one node and inbound.
type Endpoint struct {
	Node    uint
	Inbound string
}

// Score is the suspicion of an endpoint with this evidence, 0–100.
func Score(replayed, followUp uint64, followNormal float64) int {
	score := min(replayCap, replayPoints*int(min(replayed, replayCap)))
	if followUp >= followMin && float64(followUp) >= followSurge*followNormal {
		score += followPoints
	}
	return min(score, 100)
}

// EvaluateProbes recomputes every endpoint's score from the stored hours,
// moves the probed episodes, and raises endpoint.probed for each that
// began. It reads what the last flush wrote, so it lags by up to a flush.
func (d *Detector) EvaluateProbes(ctx context.Context) error {
	now := d.now()
	// The current hour counts from its start, so the window is ScoreWindow
	// of full hours plus the one under way; the normal is scaled to the
	// same length below.
	to := now.Truncate(time.Hour).Add(time.Hour).Unix()
	from := to - int64(ScoreWindow/time.Second) - 3600
	windowHours := float64(now.Unix()-from) / 3600
	weekFrom := from - 7*24*3600
	tx := d.DB.WithContext(ctx)
	win, err := d.evidence(tx, from, to)
	if err != nil {
		return err
	}
	week, err := d.evidence(tx, weekFrom, from)
	if err != nil {
		return err
	}
	var held []Suspicion
	if err := tx.Find(&held).Error; err != nil {
		return err
	}
	prev := make(map[Endpoint]Suspicion, len(held))
	for _, s := range held {
		prev[Endpoint{s.NodeID, s.Inbound}] = s
	}
	keys := make([]Endpoint, 0, len(win)+len(prev))
	for e := range win {
		keys = append(keys, e)
	}
	for e := range prev {
		if _, ok := win[e]; !ok {
			keys = append(keys, e)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Node != keys[j].Node {
			return keys[i].Node < keys[j].Node
		}
		return keys[i].Inbound < keys[j].Inbound
	})
	var alerts []Alert
	var rows []Suspicion
	var gone []Endpoint
	for _, e := range keys {
		w, p := win[e], prev[e]
		// The endpoint's own follow-up failures per window, from as much of
		// the week before as it has hours for. With less than a day of
		// them there is no normal to speak of, and a surge cannot be told
		// from an ordinary evening: it is not scored.
		normal, hasNormal := 0.0, false
		if wk, ok := week[e]; ok && wk.FirstHour > 0 {
			if hours := float64(from-wk.FirstHour) / 3600; hours >= followNormalHours {
				normal, hasNormal = float64(wk.FollowUpFail)/hours*windowHours, true
			}
		}
		followUp := w.FollowUpFail
		if !hasNormal {
			followUp = 0
		}
		s := Suspicion{
			NodeID: e.Node, Inbound: e.Inbound,
			Score:    Score(w.Replayed, followUp, normal),
			Replayed: w.Replayed, FollowUpFail: w.FollowUpFail, FollowNormal: normal,
			NoRoute: w.NoRoute, QUICStray: w.QUICStray, Failed: w.Failed, Accepted: w.Accepted,
			Probed: p.Probed, ProbedAtUnix: p.ProbedAtUnix, LastEvidence: max(p.LastEvidence, w.LastEvidence),
			UpdatedAt: now.Unix(),
		}
		switch {
		case !s.Probed && s.Score >= ProbedAt:
			s.Probed, s.ProbedAtUnix = true, now.Unix()
			alerts = append(alerts, Alert{
				Kind: KindProbed, NodeID: e.Node, Inbound: e.Inbound, At: now.Unix(),
				Detail: detailJSON(map[string]float64{
					"score": float64(s.Score), "replayed": float64(s.Replayed),
					"followUpFail": float64(s.FollowUpFail), "followNormal": normal,
				}),
			})
		case s.Probed && s.Score < QuietBelow:
			s.Probed = false
		}
		quiet := s.Replayed == 0 && s.FollowUpFail == 0 && s.NoRoute == 0 && s.QUICStray == 0
		if quiet && !s.Probed && s.ProbedAtUnix == 0 && s.LastEvidence == 0 {
			if _, ok := prev[e]; ok {
				gone = append(gone, e)
			}
			continue // nothing to remember
		}
		rows = append(rows, s)
	}
	// The episodes and their alerts are written together: an episode marked
	// begun whose alert was not stored would never be said.
	err = tx.Transaction(func(tx *gorm.DB) error {
		for _, e := range gone {
			if err := tx.Delete(&Suspicion{}, "node_id = ? AND inbound = ?", e.Node, e.Inbound).Error; err != nil {
				return err
			}
		}
		if len(rows) > 0 {
			if err := tx.Clauses(clause.OnConflict{UpdateAll: true}).CreateInBatches(rows, 200).Error; err != nil {
				return err
			}
		}
		for i := range alerts {
			if err := tx.Create(&alerts[i]).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if d.Send != nil {
		for i := range alerts {
			d.Send(ctx, alerts[i])
		}
	}
	return nil
}

// Followed reports, for each probed alert in alerts, whether a path alert
// on the same endpoint came within CalibrateWithin after it: the score's
// calibration, read back. One query for all of them.
func Followed(tx *gorm.DB, probed []Alert) (map[uint]bool, error) {
	out := map[uint]bool{}
	var first, last int64
	for _, a := range probed {
		if a.Kind != KindProbed {
			continue
		}
		out[a.ID] = false
		if first == 0 || a.At < first {
			first = a.At
		}
		last = max(last, a.At)
	}
	if len(out) == 0 {
		return out, nil
	}
	within := int64(CalibrateWithin / time.Second)
	var degraded []Alert
	if err := tx.Model(&Alert{}).Select("node_id", "inbound", "at").
		Where("kind = ? AND at >= ? AND at <= ?", KindDegraded, first, last+within).Find(&degraded).Error; err != nil {
		return nil, err
	}
	for _, a := range probed {
		if a.Kind != KindProbed {
			continue
		}
		for _, d := range degraded {
			if d.NodeID == a.NodeID && d.Inbound == a.Inbound && d.At >= a.At && d.At <= a.At+within {
				out[a.ID] = true
				break
			}
		}
	}
	return out, nil
}
