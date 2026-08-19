// Package sqlite implements every Credbound persistence port — Store plus
// the optional SessionStore, SignupStore, DomainStore, SCIMStore,
// EmailThrottleStore and OAuthStore capabilities — on SQLite through
// database/sql and sqlc-generated queries, committing each mutation's
// hash-chained audit event atomically with the change.
//
// Open the database with the modernc.org/sqlite driver using a DSN that
// carries "_pragma=foreign_keys(1)" and "_texttotime=1" (New probes both
// and rejects a misconfigured DSN), apply the schema from the module's
// migrations directory, and wire the store into credbound.Config.Store:
//
//	db, err := sql.Open("sqlite", "file:auth.db?_pragma=foreign_keys(1)&_texttotime=1")
//	store, err := sqlite.New(db)
//
// TransactionHook callbacks can regain the raw *sql.Tx through TxFrom to
// append host writes to a Credbound commit.
//
// This package is also the source of the PostgreSQL store: every file except
// dialect.go is dialect-neutral and is derived into sqlstore/postgresql by
// internal/cmd/genpostgresstore.
package sqlite
