package migrations_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/deepteams/credbound/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestApplyPostgreSQLConcurrentAndChecksum proves the two operational guards
// of the migration helper against a real PostgreSQL: instances starting
// simultaneously serialize on the advisory lock (every run succeeds, each
// migration applies exactly once), and a bookkeeping checksum that no longer
// matches the embedded file fails the next run loudly.
func TestApplyPostgreSQLConcurrentAndChecksum(t *testing.T) {
	dsn := os.Getenv("CREDBOUND_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CREDBOUND_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { db.Close() })
	reset := func() {
		if _, err := db.ExecContext(ctx, `DROP SCHEMA IF EXISTS credbound CASCADE`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS credbound_migrations`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)

	const racers = 4
	start := make(chan struct{})
	errs := make(chan error, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			<-start
			errs <- migrations.ApplyPostgreSQL(ctx, db)
		})
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent apply = %v", err)
		}
	}
	var applied int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM credbound_migrations`).Scan(&applied); err != nil || applied == 0 {
		t.Fatalf("bookkeeping rows = %d, %v", applied, err)
	}
	var distinct int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT filename) FROM credbound_migrations`).Scan(&distinct); err != nil || distinct != applied {
		t.Fatalf("duplicate bookkeeping rows: %d distinct of %d, %v", distinct, applied, err)
	}

	// A recorded checksum that no longer matches the embedded file means the
	// published migration was edited: the run must fail, not silently skip.
	var filename string
	if err := db.QueryRowContext(ctx, `SELECT filename FROM credbound_migrations ORDER BY filename LIMIT 1`).Scan(&filename); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE credbound_migrations SET checksum = 'deadbeef' WHERE filename = $1`, filename); err != nil {
		t.Fatal(err)
	}
	if err := migrations.ApplyPostgreSQL(ctx, db); err == nil || !strings.Contains(err.Error(), filename) {
		t.Fatalf("drifted migration run = %v, want a checksum error naming %s", err, filename)
	}
}
