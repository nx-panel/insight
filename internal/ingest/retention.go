package ingest

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/model"
)

// Retention windows (§4.6), constants first.
const (
	PathHourDays = 7
	PathDayDays  = 90
	compactBatch = 5000
)

// Compact folds hourly cells older than PathHourDays into daily ones and
// drops daily ones older than PathDayDays. A batch is one transaction: the
// days it adds to and the hours it removes move together, so a stop between
// batches folds nothing twice.
func Compact(ctx context.Context, db *gorm.DB, now time.Time) error {
	cut := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -PathHourDays).Unix()
	for {
		done := false
		err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var rows []model.PathHour
			if err := tx.Where("hour < ?", cut).Order("id").Limit(compactBatch).Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) == 0 {
				done = true
				return nil
			}
			days := map[cellKey]*model.PathCounters{}
			ids := make([]uint, 0, len(rows))
			for _, r := range rows {
				ids = append(ids, r.ID)
				k := cellKey{hour: r.Hour - r.Hour%86400, PathCell: r.PathCell}
				if have := days[k]; have != nil {
					addCounters(have, &r.PathCounters)
				} else {
					c := r.PathCounters
					days[k] = &c
				}
			}
			for k, c := range days {
				if err := UpsertAdd(tx, &model.PathDay{Day: k.hour, PathCell: k.PathCell, PathCounters: *c}, "day"); err != nil {
					return err
				}
			}
			return tx.Where("id IN ?", ids).Delete(&model.PathHour{}).Error
		})
		if err != nil {
			return err
		}
		if done {
			break
		}
	}
	// The signatures are kept as long as the hours, and not folded (Mode B
	// sends the hour just closed).
	if err := db.WithContext(ctx).Where("hour < ?", cut).Delete(&model.PathSigHour{}).Error; err != nil {
		return err
	}
	dayCut := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -PathDayDays).Unix()
	if err := db.WithContext(ctx).Where("day < ?", dayCut).Delete(&model.PathDay{}).Error; err != nil {
		return err
	}
	tunnelCut := now.UTC().Truncate(time.Hour).AddDate(0, 0, -model.TunnelHourDays).Unix()
	return db.WithContext(ctx).Where("hour < ?", tunnelCut).Delete(&model.TunnelHour{}).Error
}
