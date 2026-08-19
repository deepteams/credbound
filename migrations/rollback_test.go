package migrations_test

import (
	"context"
	"database/sql"
	"io/fs"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/deepteams/credbound/migrations"
	_ "modernc.org/sqlite"
)

// Migrations were covered for the forward path only: idempotence, concurrency
// and drift. The Down sections shipped untested even though goose users can
// run them, and the README's promise that timestamped files interleave with a
// host's own migrations was never exercised. These tests cover both, plus the
// parity between the two engines' migration sets.

// TestSQLiteMigrationsRollBack applies every migration and then rolls them
// back in reverse order, which is what `goose down` does. A Down section with
// a typo, or one that forgets an object its Up created, fails here instead of
// during an incident.
func TestSQLiteMigrationsRollBack(t *testing.T) {
	ctx := context.Background()
	database := openSQLite(t, "rollback_test")

	files := migrationFiles(t, migrations.SQLite())
	for _, file := range files {
		if _, err := database.ExecContext(ctx, upSection(t, migrations.SQLite(), file)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}
	if tables := credboundTables(t, database); len(tables) == 0 {
		t.Fatal("the migrations created no credbound table")
	}

	slices.Reverse(files)
	for _, file := range files {
		down := downSection(t, migrations.SQLite(), file)
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
	if err := migrations.ApplySQLite(ctx, database); err != nil {
		t.Fatalf("reapply after rollback: %v", err)
	}
	if tables := credboundTables(t, database); len(tables) == 0 {
		t.Fatal("reapplying after a rollback created no table")
	}
}

// TestSQLiteMigrationsInterleaveWithHostSchema pins the claim that Credbound's
// timestamped migrations coexist with a host's own: applying them to a
// database that already carries host tables and rows must leave that data
// untouched, keep its own bookkeeping separate, and stay idempotent.
func TestSQLiteMigrationsInterleaveWithHostSchema(t *testing.T) {
	ctx := context.Background()
	database := openSQLite(t, "interleave_test")

	if _, err := database.ExecContext(ctx, `CREATE TABLE invoices (id TEXT PRIMARY KEY, amount INTEGER NOT NULL);
INSERT INTO invoices VALUES ('inv-1', 4200);
CREATE TABLE host_migrations (filename TEXT PRIMARY KEY);
INSERT INTO host_migrations VALUES ('20260101000000_invoices.sql');`); err != nil {
		t.Fatalf("host schema: %v", err)
	}
	if err := migrations.ApplySQLite(ctx, database); err != nil {
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
	if _, err := database.ExecContext(ctx, `CREATE TABLE credits (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatalf("later host migration: %v", err)
	}
	if err := migrations.ApplySQLite(ctx, database); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM credits").Scan(&hostRows); err != nil {
		t.Fatalf("host table after the second run: %v", err)
	}
}

// TestMigrationSetsAreParallel pins the two engines against each other: a
// migration added to one and forgotten in the other would let SQLite and
// PostgreSQL drift apart, which no store test can catch since each engine is
// only ever compared with itself.
func TestMigrationSetsAreParallel(t *testing.T) {
	sqliteFiles := migrationFiles(t, migrations.SQLite())
	postgresFiles := migrationFiles(t, migrations.PostgreSQL())
	if !slices.Equal(sqliteFiles, postgresFiles) {
		t.Fatalf("migration sets diverge:\n sqlite: %v\n postgres: %v", sqliteFiles, postgresFiles)
	}
	if len(sqliteFiles) == 0 {
		t.Fatal("no migration is embedded")
	}
	if !sort.StringsAreSorted(sqliteFiles) {
		t.Fatalf("migration names are not in application order: %v", sqliteFiles)
	}
	for _, file := range sqliteFiles {
		if len(file) < 15 || strings.IndexFunc(file[:14], func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			t.Fatalf("%s does not start with a 14-digit timestamp, so it cannot interleave with a host's own", file)
		}
		for name, filesystem := range map[string]fs.FS{"sqlite": migrations.SQLite(), "postgresql": migrations.PostgreSQL()} {
			raw := readMigration(t, filesystem, file)
			if !strings.Contains(raw, "-- +goose Up") || !strings.Contains(raw, "-- +goose Down") {
				t.Fatalf("%s/%s is missing a goose section", name, file)
			}
		}
	}
}

func openSQLite(t *testing.T, name string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+name+"?mode=memory&cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
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
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'credbound%' ORDER BY name`)
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
