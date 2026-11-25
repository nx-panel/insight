package cloud

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strconv"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/model"
)

// SeedOn writes Mode B's switch as on under a fresh consent id, as SetOn
// does, built through the hour given: for a fixture (the demo), never for
// Insight itself, which goes through SetOn.
func SeedOn(ctx context.Context, gdb *gorm.DB, builtThrough int64) error {
	tx := gdb.WithContext(ctx)
	if err := model.PutState(tx, stateOn, rand.Text()); err != nil {
		return err
	}
	return model.PutState(tx, stateBuilt, strconv.FormatInt(builtThrough, 10))
}

// SeedReport writes a report as held after a check: its payload and
// signature as the cloud sent them, when it was checked and the newest
// extraction the cloud named. For a fixture (the demo).
func SeedReport(ctx context.Context, gdb *gorm.DB, payload, sig string, checkedAt, latest int64) error {
	raw, err := json.Marshal(stored{Payload: payload, Sig: sig, CheckedAt: checkedAt, Latest: latest})
	if err != nil {
		return err
	}
	return model.PutState(gdb.WithContext(ctx), stateReport, string(raw))
}
