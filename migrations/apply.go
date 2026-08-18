package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"strings"
)

// bookkeepingTable records which embedded migration files have been applied,
// together with the SHA-256 checksum of the content that was applied. It is
// deliberately distinct from goose's version table: pick either goose
// (pointed at SQLite()/PostgreSQL()) or ApplySQLite/ApplyPostgreSQL for a
// given database, never both.
const bookkeepingTable = "credbound_migrations"

// advisoryLockKey identifies the PostgreSQL advisory lock that serializes
// concurrent ApplyPostgreSQL runs across instances. Arbitrary but stable —
// it must never change once released.
const advisoryLockKey = int64(0x6372656462756e64)

// ApplySQLite applies every embedded SQLite migration that has not run yet,
// in filename order, each inside its own transaction together with its
// bookkeeping row. It is idempotent across restarts and is the minimal
// alternative for hosts that do not run goose. Concurrent runs are safe:
// SQLite's single-writer file lock serializes them and each migration
// re-checks its bookkeeping row inside the transaction. A migration file
// whose content changed after it was applied fails with a checksum error
// instead of being silently ignored.
func ApplySQLite(ctx context.Context, db *sql.DB) error {
	return apply(ctx, db, SQLite(), sqlitePlaceholder, nil)
}

// ApplyPostgreSQL applies every embedded PostgreSQL migration that has not
// run yet, in filename order, each inside its own transaction together with
// its bookkeeping row. The bookkeeping table lives on the connection's
// default search_path; the migrations themselves create and fill the
// dedicated credbound schema. It is idempotent across restarts and is the
// minimal alternative for hosts that do not run goose. Concurrent runs are
// safe: a session-level advisory lock serializes instances that start
// simultaneously, and each migration re-checks its bookkeeping row inside
// the transaction. A migration file whose content changed after it was
// applied fails with a checksum error instead of being silently ignored.
func ApplyPostgreSQL(ctx context.Context, db *sql.DB) error {
	return apply(ctx, db, PostgreSQL(), postgresPlaceholder, acquirePostgreSQLLock)
}

func sqlitePlaceholder(int) string     { return "?" }
func postgresPlaceholder(n int) string { return fmt.Sprintf("$%d", n) }

// acquirePostgreSQLLock takes the migration advisory lock on a dedicated
// connection — session-level advisory locks live and die with their
// connection, so the lock is released even if the process crashes mid-run.
func acquirePostgreSQLLock(ctx context.Context, db *sql.DB) (func(), error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", advisoryLockKey)
		_ = conn.Close()
	}, nil
}

func apply(ctx context.Context, db *sql.DB, fsys fs.FS, placeholder func(int) string, lock func(context.Context, *sql.DB) (func(), error)) error {
	if db == nil {
		return fmt.Errorf("migrations: database is required")
	}
	if lock != nil {
		unlock, err := lock(ctx, db)
		if err != nil {
			return fmt.Errorf("migrations: acquire migration lock: %w", err)
		}
		defer unlock()
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS "+bookkeepingTable+" (filename TEXT PRIMARY KEY, checksum TEXT)"); err != nil {
		return fmt.Errorf("migrations: create bookkeeping table: %w", err)
	}
	// Bookkeeping tables created before checksums existed lack the column;
	// the ALTER fails harmlessly everywhere else and the probe below is the
	// authoritative check.
	_, _ = db.ExecContext(ctx, "ALTER TABLE "+bookkeepingTable+" ADD COLUMN checksum TEXT")
	if _, err := db.ExecContext(ctx, "SELECT checksum FROM "+bookkeepingTable+" WHERE 1 = 0"); err != nil {
		return fmt.Errorf("migrations: upgrade bookkeeping table: %w", err)
	}
	entries, err := fs.ReadDir(fsys, ".") // ReadDir sorts by filename, which is goose-timestamp order
	if err != nil {
		return fmt.Errorf("migrations: list migrations: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		migration, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return fmt.Errorf("migrations: read %s: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(migration)
		checksum := hex.EncodeToString(sum[:])
		applied, recorded, err := recordedChecksum(ctx, db, placeholder, entry.Name())
		if err != nil {
			return err
		}
		if applied {
			if err := reconcileChecksum(ctx, db, placeholder, entry.Name(), recorded, checksum); err != nil {
				return err
			}
			continue
		}
		up, _, _ := strings.Cut(string(migration), "-- +goose Down")
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrations: begin %s: %w", entry.Name(), err)
		}
		// Re-check inside the transaction: an instance that started before the
		// lock was taken (SQLite has none) may have applied this migration
		// after the read above; the bookkeeping primary key backstops any
		// residual race by failing the duplicate insert.
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+bookkeepingTable+" WHERE filename = "+placeholder(1), entry.Name()).Scan(&count); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrations: check %s: %w", entry.Name(), err)
		}
		if count > 0 {
			_ = tx.Rollback()
			continue
		}
		if _, err := tx.ExecContext(ctx, up); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrations: apply %s: %w", entry.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO "+bookkeepingTable+" (filename, checksum) VALUES ("+placeholder(1)+", "+placeholder(2)+")", entry.Name(), checksum); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrations: record %s: %w", entry.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrations: commit %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func recordedChecksum(ctx context.Context, db *sql.DB, placeholder func(int) string, filename string) (bool, string, error) {
	var recorded sql.NullString
	err := db.QueryRowContext(ctx, "SELECT checksum FROM "+bookkeepingTable+" WHERE filename = "+placeholder(1), filename).Scan(&recorded)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("migrations: check %s: %w", filename, err)
	}
	return true, recorded.String, nil
}

// reconcileChecksum guards an already-applied migration: a matching checksum
// passes, a row recorded before checksums existed adopts the current content,
// and any other difference means the embedded file changed after it was
// applied — a drift that must fail loudly rather than run half-old schemas.
func reconcileChecksum(ctx context.Context, db *sql.DB, placeholder func(int) string, filename, recorded, checksum string) error {
	switch recorded {
	case checksum:
		return nil
	case "":
		if _, err := db.ExecContext(ctx, "UPDATE "+bookkeepingTable+" SET checksum = "+placeholder(1)+" WHERE filename = "+placeholder(2)+" AND checksum IS NULL", checksum, filename); err != nil {
			return fmt.Errorf("migrations: backfill checksum for %s: %w", filename, err)
		}
		return nil
	default:
		return fmt.Errorf("migrations: %s changed after it was applied (embedded checksum %s, recorded %s); published migrations are immutable — ship a new migration instead", filename, checksum, recorded)
	}
}
