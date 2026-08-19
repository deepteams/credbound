package migrations_test

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/deepteams/credbound/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Migrations were covered for the forward path only: idempotence, concurrency
// and drift. The Down sections shipped untested even though goose users can
// run them, and the README's promise that timestamped files interleave with a
// host's own migrations was never exercised. These tests cover both.

// TestMigrationsRollBack applies every migration and then rolls them back in
// reverse order, which is what `goose down` does. A Down section with a typo,
// or one that forgets an object its Up created, fails here instead of during
// an incident.
func TestMigrationsRollBack(t *testing.T) {
	ctx := context.Background()
	database := openPostgreSQL(t)

	files := migrationFiles(t, migrations.PostgreSQL())
	for _, file := range files {
		if _, err := database.ExecContext(ctx, upSection(t, migrations.PostgreSQL(), file)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}
	if tables := credboundTables(t, database); len(tables) == 0 {
		t.Fatal("the migrations created no credbound table")
	}

	slices.Reverse(files)
	for _, file := range files {
		down := downSection(t, migrations.PostgreSQL(), file)
		if strings.TrimSpace(down) == "" {
			t.Fatalf("%s ships no Down section", file)
		}
		if _, err := database.ExecContext(ctx, down); err != nil {
			t.Fatalf("roll back %s: %v", file, err)
		}
	}
	if remaining := credboundTables(t, database); len(remaining) != 0 {
		t.Fatalf("rolling back left %v behind", remaining)
	}

	// The schema must be reapplicable after a full rollback, which is what a
	// host does when it retries a failed release.
	if err := migrations.ApplyPostgreSQL(ctx, database); err != nil {
		t.Fatalf("reapply after rollback: %v", err)
	}
	if tables := credboundTables(t, database); len(tables) == 0 {
		t.Fatal("reapplying after a rollback created no table")
	}
}

// TestMigrationsInterleaveWithHostSchema pins the claim that Credbound's
// timestamped migrations coexist with a host's own: applying them to a
// database that already carries host tables and rows must leave that data
// untouched, keep its own bookkeeping separate, and stay idempotent.
func TestMigrationsInterleaveWithHostSchema(t *testing.T) {
	ctx := context.Background()
	database := openPostgreSQL(t)

	if _, err := database.ExecContext(ctx, `CREATE TABLE invoices (id text PRIMARY KEY, amount bigint NOT NULL);
INSERT INTO invoices VALUES ('inv-1', 4200);
CREATE TABLE host_migrations (filename text PRIMARY KEY);
INSERT INTO host_migrations VALUES ('20260101000000_invoices.sql');`); err != nil {
		t.Fatalf("host schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TABLE IF EXISTS invoices, host_migrations, credits`)
	})
	if err := migrations.ApplyPostgreSQL(ctx, database); err != nil {
		t.Fatalf("apply over a host schema: %v", err)
	}

	var amount int
	if err := database.QueryRowContext(ctx, "SELECT amount FROM invoices WHERE id = 'inv-1'").Scan(&amount); err != nil || amount != 4200 {
		t.Fatalf("host row after migration = %d, %v", amount, err)
	}
	var hostRows int
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM host_migrations").Scan(&hostRows); err != nil || hostRows != 1 {
		t.Fatalf("host bookkeeping = %d, %v", hostRows, err)
	}
	if tables := credboundTables(t, database); len(tables) == 0 {
		t.Fatal("no credbound table was created next to the host schema")
	}

	// A host migration landing after Credbound's, then a second Credbound
	// run: neither disturbs the other.
	if _, err := database.ExecContext(ctx, `CREATE TABLE credits (id text PRIMARY KEY)`); err != nil {
		t.Fatalf("later host migration: %v", err)
	}
	if err := migrations.ApplyPostgreSQL(ctx, database); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM credits").Scan(&hostRows); err != nil {
		t.Fatalf("host table after the second run: %v", err)
	}
}

// TestMigrationNamesInterleave pins the naming contract the README relies on:
// every file starts with a 14-digit timestamp so lexical order is application
// order and a host's own migrations can be sorted in between, and every file
// carries both goose sections.
func TestMigrationNamesInterleave(t *testing.T) {
	files := migrationFiles(t, migrations.PostgreSQL())
	if len(files) == 0 {
		t.Fatal("no migration is embedded")
	}
	if !sort.StringsAreSorted(files) {
		t.Fatalf("migration names are not in application order: %v", files)
	}
	for _, file := range files {
		if len(file) < 15 || strings.IndexFunc(file[:14], func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			t.Fatalf("%s does not start with a 14-digit timestamp, so it cannot interleave with a host's own", file)
		}
		raw := readMigration(t, migrations.PostgreSQL(), file)
		if !strings.Contains(raw, "-- +goose Up") || !strings.Contains(raw, "-- +goose Down") {
			t.Fatalf("%s is missing a goose section", file)
		}
	}
}

// openPostgreSQL hands out a connection on a database wiped of Credbound
// objects, so each test starts from the state a fresh deployment would.
func openPostgreSQL(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("CREDBOUND_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("CREDBOUND_POSTGRES_DSN is not set")
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	database := stdlib.OpenDB(*config)
	t.Cleanup(func() { database.Close() })
	reset := func() {
		if _, err := database.ExecContext(context.Background(), `DROP SCHEMA IF EXISTS credbound CASCADE`); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(context.Background(), `DROP TABLE IF EXISTS credbound_migrations`); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	t.Cleanup(reset)
	return database
}

func migrationFiles(t *testing.T, filesystem fs.FS) []string {
	t.Helper()
	entries, err := fs.ReadDir(filesystem, ".")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

func readMigration(t *testing.T, filesystem fs.FS, name string) string {
	t.Helper()
	raw, err := fs.ReadFile(filesystem, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func upSection(t *testing.T, filesystem fs.FS, name string) string {
	t.Helper()
	return strings.Split(readMigration(t, filesystem, name), "-- +goose Down")[0]
}

func downSection(t *testing.T, filesystem fs.FS, name string) string {
	t.Helper()
	parts := strings.SplitN(readMigration(t, filesystem, name), "-- +goose Down", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// credboundTables lists the library's own tables, ignoring the host's.
func credboundTables(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.QueryContext(context.Background(),
		`SELECT table_name FROM information_schema.tables WHERE table_schema = 'credbound' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tables
}
