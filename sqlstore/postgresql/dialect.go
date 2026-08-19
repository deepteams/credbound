package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/postgresql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This file carries the store's plumbing: construction, the streaming read
// surface, error classification and the transaction capability. The statements
// themselves live in queries.go and in sql/queries/postgresql.sql.

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

// scanRows is the streaming read surface the list operations consume; pgx.Rows
// satisfies it directly.
type scanRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// query streams one of the statements in queries.go through pgx.
func (s *Store) query(ctx context.Context, statement string, args ...any) (scanRows, error) {
	rows, err := s.rows.Query(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

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
