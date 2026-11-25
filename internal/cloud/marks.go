package cloud

import (
	"context"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/tunnels"
)

// The kinds of model.HourMark.
const (
	markDegraded = "degraded"
	markOutage   = "outage"
	markBlocked  = "blocked"
	markCut      = "cut"
)

// Mark records one evaluation of the detector (detect.Reading, handed
// over as it is made) for the hour of its moment, with the tunnels a
// status of this run found down: a batch's verdicts are what was recorded
// for its own hour (build), so an hour built late (waiting for the shapes,
// or after a restart) carries the same verdicts as one built on time.
//
// The write and the read of cloud_built_through are one transaction under
// cloud_on's lock, as advance is: nothing is recorded for an hour once it
// is built, and a record that lands between a build's count of an hour
// and its advance makes the hour be built again. With Mode B on, the
// records of the hours not yet built and not older than Keep are kept;
// off, nothing is recorded and nothing kept, so the hour in progress at a
// consent carries the verdicts read from the consent on.
func (c *Cloud) Mark(ctx context.Context, r detect.Reading) error {
	var views []tunnels.View
	if c.Sources.Tunnels != nil {
		views = c.Sources.Tunnels()
	}
	return mark(ctx, c.DB, r, views)
}

func mark(ctx context.Context, db *gorm.DB, r detect.Reading, views []tunnels.View) error {
	hour := hourOf(r.At)
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var on, built model.State
		if err := tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).Where("key = ?", stateOn).Limit(1).Find(&on).Error; err != nil {
			return err
		}
		if on.Value == "" {
			return tx.Where("hour <= ?", hour).Delete(&model.HourMark{}).Error
		}
		if err := tx.Where("key = ?", stateBuilt).Limit(1).Find(&built).Error; err != nil {
			return err
		}
		last, err := strconv.ParseInt(built.Value, 10, 64)
		if err != nil {
			last = -1 // none built yet
		}
		// The hours built, and those too old to be: hours are whole, so the
		// one bound is the later of the two.
		if err := tx.Where("hour <= ?", max(last, oldestBuilt(r.At)-1)).Delete(&model.HourMark{}).Error; err != nil {
			return err
		}
		rows := marksAt(r, views, hour)
		if hour <= last || len(rows) == 0 {
			return nil
		}
		return tx.Clauses(clause.OnConflict{DoNothing: true}).CreateInBatches(rows, 200).Error
	})
}

// marksAt are the rows one evaluation and the tunnels give hour; build
// turns them into verdicts.
func marksAt(r detect.Reading, views []tunnels.View, hour int64) []model.HourMark {
	var rows []model.HourMark
	for k := range r.Degraded {
		rows = append(rows, model.HourMark{Hour: hour, Kind: markDegraded, NodeID: k.Node, Inbound: k.Inbound, ASN: k.ASN, Network: k.Network})
	}
	for asn := range r.Outages {
		rows = append(rows, model.HourMark{Hour: hour, Kind: markOutage, ASN: asn})
	}
	for node := range nodesBlocked(r.Judged, r.Degraded, r.Outages) {
		rows = append(rows, model.HourMark{Hour: hour, Kind: markBlocked, NodeID: node})
	}
	for _, v := range views {
		if v.State == tunnels.Down && v.Judged {
			rows = append(rows, model.HourMark{Hour: hour, Kind: markCut, NodeID: v.RelayID})
		}
	}
	return rows
}

// hourOf is the start of the hour t falls in, in unix seconds.
func hourOf(t time.Time) int64 { return t.Unix() / 3600 * 3600 }

// oldestBuilt is the oldest hour a build at now still makes (Keep back).
func oldestBuilt(now time.Time) int64 { return hourOf(now.Add(-Keep)) }

// hourMarks is what was recorded for one hour: each thing any evaluation
// in it found.
type hourMarks struct {
	degraded map[detect.Key]bool
	outages  map[uint32]bool
	blocked  map[uint]bool
	cut      map[uint]bool
}

// marksOf reads the marks of hour. An hour nothing was recorded for
// (Mode B off, or Insight not running or not judging through it) reads as
// fine.
func marksOf(q *gorm.DB, hour int64) (hourMarks, error) {
	m := hourMarks{degraded: map[detect.Key]bool{}, outages: map[uint32]bool{}, blocked: map[uint]bool{}, cut: map[uint]bool{}}
	var rows []model.HourMark
	if err := q.Where("hour = ?", hour).Find(&rows).Error; err != nil {
		return m, err
	}
	for _, r := range rows {
		switch r.Kind {
		case markDegraded:
			m.degraded[detect.Key{Node: r.NodeID, Inbound: r.Inbound, ASN: r.ASN, Network: r.Network}] = true
		case markOutage:
			m.outages[r.ASN] = true
		case markBlocked:
			m.blocked[r.NodeID] = true
		case markCut:
			m.cut[r.NodeID] = true
		}
	}
	return m, nil
}

// countMarks is how many rows hour holds: what advance checks a build read.
func countMarks(q *gorm.DB, hour int64) (int64, error) {
	var n int64
	err := q.Model(&model.HourMark{}).Where("hour = ?", hour).Count(&n).Error
	return n, err
}
