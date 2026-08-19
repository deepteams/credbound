package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/postgresql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This file carries everything genuinely PostgreSQL-specific: construction,
// error classification, statement translation and the concurrency strategy. It
// is written by hand and is NOT generated. Its counterpart is
// sqlstore/sqlite/dialect.go; every other file in this package is derived from
// the SQLite store by internal/cmd/genpostgresstore.

// RowQuerier is the pgx query surface the store streams paginated reads
// through; both *pgxpool.Pool and *pgx.Conn satisfy it, but only a pool is
// safe for concurrent use.
type RowQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// Store is the PostgreSQL-backed implementation of the Credbound persistence
// ports. It is safe for concurrent use: mutations run inside transactions
// that commit the audit event atomically with the change, and list
// operations stream rows under a per-query timeout (WithStreamTimeout).
// Method semantics, sentinel errors and pagination behavior are specified
// on the credbound port interfaces.
type Store struct {
	db            *sql.DB
	rows          RowQuerier
	queries       *db.Queries
	streamTimeout time.Duration
	locks         locks
}

// Option customizes a Store during New.
type Option func(*Store)

// WithStreamTimeout overrides the 30 second per-query timeout that bounds
// streaming list operations. New rejects non-positive values.
func WithStreamTimeout(timeout time.Duration) Option {
	return func(store *Store) { store.streamTimeout = timeout }
}

// New builds the PostgreSQL store from two views of the same database: a
// *sql.DB used by the sqlc-generated queries for transactional mutations
// (open one with pgx's stdlib.OpenDB or stdlib.OpenDBFromPool), and a pgx
// RowQuerier used to stream paginated reads. In production pass a
// *pgxpool.Pool as the RowQuerier — a single *pgx.Conn is not safe for
// concurrent use.
func New(database *sql.DB, rows RowQuerier, options ...Option) (*Store, error) {
	if database == nil || rows == nil {
		return nil, fmt.Errorf("%w: PostgreSQL database/sql and pgx row querier are required", credbound.ErrInvalidInput)
	}
	store := &Store{db: database, rows: rows, queries: db.New(database), streamTimeout: 30 * time.Second}
	for _, option := range options {
		option(store)
	}
	if store.streamTimeout <= 0 {
		return nil, fmt.Errorf("%w: stream timeout must be positive", credbound.ErrInvalidInput)
	}
	return store, nil
}

// scanRows is the streaming read surface the dialect-neutral list operations
// consume; pgx.Rows satisfies it directly.
type scanRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// query runs one of the shared statements, which are written in the SQLite
// dialect because the SQLite store is the source this package is derived from.
// translate converts them to PostgreSQL before they reach the server.
func (s *Store) query(ctx context.Context, statement string, args ...any) (scanRows, error) {
	rows, err := s.rows.Query(ctx, translate(statement), args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// translate rewrites a shared statement into PostgreSQL: "?" placeholders
// become "$1", "$2", … in order, and the prefix-namespaced table names become
// schema-qualified ones, since PostgreSQL keeps every object in the dedicated
// "credbound" schema. Placeholders inside string literals are left alone.
//
// This runs per streamed query rather than once at startup; at a few hundred
// bytes per statement it costs far less than the round trip it precedes, and
// keeping it here means the shared files hold exactly one copy of each
// statement.
func translate(statement string) string {
	var out strings.Builder
	out.Grow(len(statement) + 16)
	index := 1
	inLiteral := false
	for _, char := range statement {
		switch {
		case char == '\'':
			inLiteral = !inLiteral
		case char == '?' && !inLiteral:
			out.WriteByte('$')
			out.WriteString(strconv.Itoa(index))
			index++
			continue
		}
		out.WriteRune(char)
	}
	return strings.ReplaceAll(out.String(), "credbound_", "credbound.")
}

// nullableUUID keeps an empty cursor id out of a typed comparison: PostgreSQL
// rejects the empty string against a uuid column, so the shared statements
// pass NULL and gate the comparison on a separate boolean parameter.
func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// locks is the concurrency strategy. PostgreSQL has row-level locking, so the
// read-then-write invariant checks inside a mutation (last root administrator,
// sole workspace admin, the DCR registration count) are protected by the Lock*
// queries the shared code calls — SELECT … FOR UPDATE here, plain reads on
// SQLite — and the singleton audit chain head is taken FOR UPDATE by its own
// query. Mutations therefore run concurrently and nothing is serialized in
// process, which is why write is a no-op: the SQLite store holds a mutex here
// because it has no row locks to fall back on.
type locks struct{}

func (l *locks) write() func() { return func() {} }

// Tx is the PostgreSQL transaction capability exposed only during a Credbound
// TransactionHook. SQL returns nil after the callback has completed.
type Tx struct {
	sqlTx atomic.Pointer[sql.Tx]
	audit credbound.AuditEvent
}

func newTx(sqlTx *sql.Tx, audit credbound.AuditEvent) *Tx {
	handle := &Tx{audit: audit}
	handle.sqlTx.Store(sqlTx)
	return handle
}

// Kind reports credbound.StorePostgreSQL.
func (t *Tx) Kind() credbound.StoreKind { return credbound.StorePostgreSQL }

// Audit returns the audit event being committed with this transaction.
func (t *Tx) Audit() credbound.AuditEvent { return t.audit }

// SQL returns the live transaction so a hook can append host writes to the
// commit, or nil once the hook callback has completed.
func (t *Tx) SQL() *sql.Tx {
	if t == nil {
		return nil
	}
	return t.sqlTx.Load()
}

func (t *Tx) close() {
	if t != nil {
		t.sqlTx.Store(nil)
	}
}

// TxFrom converts a generic Credbound transaction into the live PostgreSQL
// capability. It returns false for another store or an expired callback.
func TxFrom(tx credbound.Tx) (*Tx, bool) {
	handle, ok := tx.(*Tx)
	if !ok || handle.SQL() == nil {
		return nil, false
	}
	return handle, true
}

// pgConstraintClass is the SQLSTATE class shared by every integrity
// constraint violation (unique, foreign key, not null, check, restrict).
const pgConstraintClass = "23"

// mapError translates a driver error into the Credbound sentinels. A
// constraint violation is classified by the driver's typed SQLSTATE rather
// than a message substring, which was locale-fragile and wording-fragile.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return credbound.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && len(pgErr.Code) >= 2 && pgErr.Code[:2] == pgConstraintClass {
		return fmt.Errorf("%w: %v", credbound.ErrConflict, err)
	}
	return err
}

// SCIM list filters are the one place where the two engines genuinely disagree
// on SQL, so the fragments live here and the builder in scim.go stays shared.
// PostgreSQL casts its uuid primary key to compare it against the filter text,
// and walks the jsonb array with jsonb_array_elements.
const (
	scimIDFilter    = ` AND id::text = ?`
	scimEmailFilter = ` AND EXISTS (SELECT 1 FROM jsonb_array_elements(emails_json) e WHERE e->>'value' = ?)`
)
