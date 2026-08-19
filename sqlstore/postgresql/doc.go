// Package postgresql implements every Credbound persistence port — Store
// plus the optional SessionStore, SignupStore, DomainStore, SCIMStore,
// EmailThrottleStore and OAuthStore capabilities — on PostgreSQL, pairing
// sqlc-generated database/sql queries for transactional mutations with pgx
// streaming for paginated reads, and committing each mutation's hash-chained
// audit event atomically with the change.
//
// All objects live in the dedicated "credbound" schema; apply the module's
// migrations before use. Open one pgx pool and hand the store both views of
// it, then wire the store into credbound.Config.Store:
//
//	pool, err := pgxpool.New(ctx, dsn)
//	store, err := postgresql.New(stdlib.OpenDBFromPool(pool), pool)
//
// TransactionHook callbacks can regain the raw *sql.Tx through TxFrom to
// append host writes to a Credbound commit.
//
// Except for dialect.go and this file, which are written by hand, the package
// is derived from sqlstore/sqlite by internal/cmd/genpostgresstore. Change the
// SQLite store and re-run "make generate".
package postgresql
