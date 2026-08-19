package postgresql_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/internal/storetest"
	postgresstore "github.com/deepteams/credbound/sqlstore/postgresql"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// TestConformance runs the shared store conformance suite against a real
// PostgreSQL. The generated store is excluded from the coverage measurement
// and, before this suite existed, was exercised by a single integration test
// over a lone *pgx.Conn; the flows below run the Manager against the
// production wiring New documents — a *pgxpool.Pool — including the
// concurrency flows a single connection cannot serve.
func TestConformance(t *testing.T) {
	dsn := os.Getenv("CREDBOUND_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CREDBOUND_POSTGRES_DSN is not set")
	}
	storetest.Run(t, storetest.Factory{
		Name: "postgresql",
		New:  func(t *testing.T) credbound.Store { return newConformanceStore(t, dsn) },
	})
}

// newConformanceStore resets the dedicated `credbound` schema and reapplies
// the shipped migrations, so every flow starts from an empty database. The
// suite calls it once per flow, which is what makes resetting a shared
// database safe here.
func newConformanceStore(t *testing.T, dsn string) credbound.Store {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// Every Credbound object lives in the dedicated `credbound` schema, so a
	// clean slate is the schema itself, recreated by the first migration.
	if _, err := pool.Exec(ctx, `DROP SCHEMA IF EXISTS credbound CASCADE`); err != nil {
		t.Fatal(err)
	}

	database := stdlib.OpenDBFromPool(pool)
	t.Cleanup(func() { database.Close() })
	applyPostgreSQLMigrations(t, database)

	store, err := postgresstore.New(database, pool, postgresstore.WithStreamTimeout(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
