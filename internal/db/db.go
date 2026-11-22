// Package db opens Insight's database — SQLite by default, PostgreSQL by the
// install's choice — and migrates it. The pure-Go SQLite driver keeps the
// build free of cgo, as the panel's is.
package db

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// cellColumns is a path cell's identity, the unique key both path tables
// upsert on. A unique index written out rather than tagged: PathCell is
// embedded in two tables, and an index name is per database in SQLite.
const cellColumns = "node_id, inbound, client_asn, country, region, network, source_kind"

// Open connects and migrates.
func Open(c config.Config) (*gorm.DB, error) {
	gc := &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)}
	var (
		gdb *gorm.DB
		err error
	)
	if c.Driver == config.DriverPostgres {
		gdb, err = gorm.Open(postgres.Open(c.DSN), gc)
		if err == nil {
			if sqlDB, e := gdb.DB(); e == nil {
				sqlDB.SetMaxOpenConns(10)
				sqlDB.SetMaxIdleConns(3)
				sqlDB.SetConnMaxLifetime(30 * time.Minute)
			}
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(c.DSN), 0o700); err != nil {
			return nil, err
		}
		gdb, err = gorm.Open(sqlite.Open(sqliteDSN(c.DSN)), gc)
		if err == nil {
			if sqlDB, e := gdb.DB(); e == nil {
				sqlDB.SetMaxOpenConns(4)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("open the %s database: %w", c.Driver, err)
	}
	if err := Migrate(gdb); err != nil {
		return nil, err
	}
	return gdb, nil
}

// Migrate creates the tables and the cell indexes.
func Migrate(gdb *gorm.DB) error {
	if err := gdb.AutoMigrate(model.All()...); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	for _, stmt := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS path_hours_cell ON path_hours (hour, " + cellColumns + ")",
		"CREATE UNIQUE INDEX IF NOT EXISTS path_days_cell ON path_days (day, " + cellColumns + ")",
	} {
		if err := gdb.Exec(stmt).Error; err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// sqliteDSN turns on WAL, a busy timeout and immediate transactions, as the
// panel and Notif do.
func sqliteDSN(path string) string {
	return "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_txlock=immediate"
}
