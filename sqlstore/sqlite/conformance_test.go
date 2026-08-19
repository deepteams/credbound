package sqlite_test

import (
	"database/sql"
	"io/fs"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/internal/storetest"
	"github.com/deepteams/credbound/migrations"
	sqlitestore "github.com/deepteams/credbound/sqlstore/sqlite"
	_ "modernc.org/sqlite"
)

// TestConformance runs the shared store conformance suite against a
// migration-applied SQLite database, so the Manager flows the root package
// only exercises in memory are proven on real persistence too.
func TestConformance(t *testing.T) {
	storetest.Run(t, storetest.Factory{Name: "sqlite", New: newConformanceStore})
}

// conformanceDatabases numbers the shared-cache databases so a flow asking
// for a second store gets a second, empty one instead of reopening the first.
var conformanceDatabases atomic.Uint64

func newConformanceStore(t *testing.T) credbound.Store {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_") + "_" + strconv.FormatUint(conformanceDatabases.Add(1), 10)
	dsn := "file:" + name + "?mode=memory&cache=shared&_pragma=foreign_keys(1)&_texttotime=1"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	migrationFS := migrations.SQLite()
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		migration, err := fs.ReadFile(migrationFS, entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(strings.Split(string(migration), "-- +goose Down")[0]); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
	}
	store, err := sqlitestore.New(database, sqlitestore.WithStreamTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
