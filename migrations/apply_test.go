package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/deepteams/credbound/migrations"
	_ "modernc.org/sqlite"
)

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
