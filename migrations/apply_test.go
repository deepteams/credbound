package migrations_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/deepteams/credbound/migrations"
	_ "modernc.org/sqlite"
)

// TestApplySQLiteIsIdempotent pins the shipped SQLite migrations (DATA-001):
// applying them yields a usable schema with bookkeeping, and a second run
// applies nothing and succeeds.
func TestApplySQLiteIsIdempotent(t *testing.T) {
	db, err := sql.Open("sqlite", "file:apply_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := migrations.ApplySQLite(ctx, db); err != nil {
		t.Fatal(err)
	}
	var users int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM credbound_users").Scan(&users); err != nil || users != 0 {
		t.Fatalf("migrated schema unusable: %d, %v", users, err)
	}
	var applied int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM credbound_migrations").Scan(&applied); err != nil || applied == 0 {
		t.Fatalf("bookkeeping = %d, %v", applied, err)
	}
	// A second run applies nothing and succeeds.
	if err := migrations.ApplySQLite(ctx, db); err != nil {
		t.Fatal(err)
	}
	var again int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM credbound_migrations").Scan(&again); err != nil || again != applied {
		t.Fatalf("second run changed bookkeeping: %d -> %d, %v", applied, again, err)
	}
	if err := migrations.ApplySQLite(ctx, nil); err == nil {
		t.Fatal("nil database accepted")
	}
}

// TestApplySQLiteChecksumGuard pins the drift guard: a bookkeeping row whose
// checksum no longer matches the embedded file fails loudly, and a row
// recorded before checksums existed (NULL) adopts the current content instead
// of failing.
func TestApplySQLiteChecksumGuard(t *testing.T) {
	db, err := sql.Open("sqlite", "file:apply_checksum_test?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := migrations.ApplySQLite(ctx, db); err != nil {
		t.Fatal(err)
	}
	var filename, checksum string
	if err := db.QueryRowContext(ctx, "SELECT filename, checksum FROM credbound_migrations ORDER BY filename LIMIT 1").Scan(&filename, &checksum); err != nil || checksum == "" {
		t.Fatalf("recorded checksum = %q, %v", checksum, err)
	}
	// A pre-checksum row (NULL) is backfilled with the embedded content.
	if _, err := db.ExecContext(ctx, "UPDATE credbound_migrations SET checksum = NULL WHERE filename = ?", filename); err != nil {
		t.Fatal(err)
	}
	if err := migrations.ApplySQLite(ctx, db); err != nil {
		t.Fatalf("backfill run = %v", err)
	}
	var backfilled string
	if err := db.QueryRowContext(ctx, "SELECT checksum FROM credbound_migrations WHERE filename = ?", filename).Scan(&backfilled); err != nil || backfilled != checksum {
		t.Fatalf("backfilled checksum = %q, want %q (%v)", backfilled, checksum, err)
	}
	// A recorded checksum that no longer matches the embedded file means the
	// published migration was edited: the run must fail, not silently skip.
	if _, err := db.ExecContext(ctx, "UPDATE credbound_migrations SET checksum = 'deadbeef' WHERE filename = ?", filename); err != nil {
		t.Fatal(err)
	}
	if err := migrations.ApplySQLite(ctx, db); err == nil || !strings.Contains(err.Error(), filename) {
		t.Fatalf("drifted migration run = %v, want a checksum error naming %s", err, filename)
	}
}
