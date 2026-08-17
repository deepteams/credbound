package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"strings"
)

// bookkeepingTable records which embedded migration files have been applied.
// It is deliberately distinct from goose's version table: pick either goose
// (pointed at SQLite()/PostgreSQL()) or ApplySQLite/ApplyPostgreSQL for a
// given database, never both.
const bookkeepingTable = "credbound_migrations"

// ApplySQLite applies every embedded SQLite migration that has not run yet,
// in filename order, each inside its own transaction together with its
// bookkeeping row. It is idempotent across restarts and is the minimal
// alternative for hosts that do not run goose.
func ApplySQLite(ctx context.Context, db *sql.DB) error {
	return apply(ctx, db, SQLite(), "?")
}

// ApplyPostgreSQL applies every embedded PostgreSQL migration that has not
// run yet, in filename order, each inside its own transaction together with
// its bookkeeping row. The bookkeeping table lives on the connection's
// default search_path; the migrations themselves create and fill the
// dedicated credbound schema. It is idempotent across restarts and is the
// minimal alternative for hosts that do not run goose.
func ApplyPostgreSQL(ctx context.Context, db *sql.DB) error {
	return apply(ctx, db, PostgreSQL(), "$1")
}

func apply(ctx context.Context, db *sql.DB, fsys fs.FS, placeholder string) error {
	if db == nil {
		return fmt.Errorf("migrations: database is required")
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+bookkeepingTable+" (filename TEXT PRIMARY KEY)"); err != nil {
		return fmt.Errorf("migrations: create bookkeeping table: %w", err)
	}
	entries, err := fs.ReadDir(fsys, ".") // ReadDir sorts by filename, which is goose-timestamp order
	if err != nil {
		return fmt.Errorf("migrations: list migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		var applied int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+bookkeepingTable+" WHERE filename = "+placeholder, entry.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("migrations: check %s: %w", entry.Name(), err)
		}
		if applied > 0 {
			continue
		}
		migration, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return fmt.Errorf("migrations: read %s: %w", entry.Name(), err)
		}
		up, _, _ := strings.Cut(string(migration), "-- +goose Down")
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrations: begin %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, up); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrations: apply %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+bookkeepingTable+" (filename) VALUES ("+placeholder+")", entry.Name()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrations: record %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrations: commit %s: %w", entry.Name(), err)
		}
	}
	return nil
}
