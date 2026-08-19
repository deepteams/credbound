package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
	sqlitedriver "modernc.org/sqlite"
)

// This file carries everything genuinely SQLite-specific: construction, error
// classification, statement translation and the concurrency strategy. Its
// counterpart is sqlstore/postgresql/dialect.go, hand-written against the same
// internal contract. Every other file in this package is dialect-neutral and
// is derived into the postgresql package by internal/cmd/genpostgresstore.

// Store is the SQLite-backed implementation of the Credbound persistence
// ports. It is safe for concurrent use: mutations run inside transactions
// that commit the audit event atomically with the change, and list
// operations stream rows under a per-query timeout (WithStreamTimeout).
// Method semantics, sentinel errors and pagination behavior are specified
// on the credbound port interfaces.
type Store struct {
	db            *sql.DB
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

// New wraps an already-opened SQLite database. The store issues no PRAGMAs
// itself: the connection must be opened with the modernc.org/sqlite driver
// and a DSN carrying "_pragma=foreign_keys(1)" (referential integrity,
// which the revocation cascades depend on) and "_texttotime=1" (TEXT
// timestamp scanning):
//
//	sql.Open("sqlite", "file:auth.db?_pragma=foreign_keys(1)&_texttotime=1")
//
// New probes the connection and reports ErrInvalidInput when either
// parameter is missing, so a misconfigured DSN fails construction instead
// of corrupting behavior quietly at runtime.
func New(database *sql.DB, options ...Option) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: sqlite database is required", credbound.ErrInvalidInput)
	}
	store := &Store{db: database, queries: db.New(database), streamTimeout: 30 * time.Second}
	for _, option := range options {
		option(store)
	}
	if store.streamTimeout <= 0 {
		return nil, fmt.Errorf("%w: stream timeout must be positive", credbound.ErrInvalidInput)
	}
	if err := verifyConnection(database); err != nil {
		return nil, err
	}
	return store, nil
}

// verifyConnection probes the DSN parameters the store depends on.
// foreign_keys is per-connection in SQLite, so only a DSN pragma — applied
// by the driver to every pooled connection — makes the check meaningful
// beyond the probed connection.
func verifyConnection(database *sql.DB) error {
	var enforced int
	if err := database.QueryRow("PRAGMA foreign_keys").Scan(&enforced); err != nil {
		return fmt.Errorf("probe sqlite foreign_keys: %w", err)
	}
	if enforced != 1 {
		return fmt.Errorf("%w: the sqlite DSN must carry _pragma=foreign_keys(1)", credbound.ErrInvalidInput)
	}
	var probe time.Time
	if err := database.QueryRow("SELECT CAST('2000-01-02 03:04:05' AS TEXT)").Scan(&probe); err != nil {
		return fmt.Errorf("%w: the sqlite DSN must carry _texttotime=1", credbound.ErrInvalidInput)
	}
	return nil
}

// scanRows is the streaming read surface the dialect-neutral list operations
// consume; database/sql and pgx both provide it, modulo Close's signature.
type scanRows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// query runs one of this package's hand-written statements. The statements are
// written once, in the portable form both engines accept; the PostgreSQL store
// rewrites their placeholders and table names in its own query method, so this
// one only has to run them.
func (s *Store) query(ctx context.Context, statement string, args ...any) (scanRows, error) {
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	return sqlRows{rows}, nil
}

// sqlRows adapts *sql.Rows to scanRows. Discarding Close's error is safe: it
// only ever repeats an error Err has already reported.
type sqlRows struct{ *sql.Rows }

func (r sqlRows) Close() { _ = r.Rows.Close() }

// nullableUUID keeps an empty cursor id out of a typed comparison. SQLite
// would accept the empty string, but PostgreSQL rejects it against a uuid
// column, so the shared statements pass NULL on both engines and gate the
// comparison on a separate boolean parameter.
func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// locks is the concurrency strategy. SQLite is a single-writer database with
// no row-level locking, so the read-then-write invariant checks inside a
// mutation (last root administrator, sole workspace admin, the singleton audit
// chain head) are only safe if mutations do not interleave. Holding writeMu for
// the duration of each write transaction guarantees that within a process;
// reads never take it, so streaming list operations stay concurrent. Across
// processes sharing one database file, open the connection with
// "_txlock=immediate" so the file-level write lock provides the same guarantee.
//
// It is held across the TransactionHook callback, so a hook must append to the
// commit's transaction through TxFrom and must not call back into a Store
// mutation — doing so self-deadlocks on this non-reentrant mutex (it would also
// be a nested-transaction error on the same connection).
//
// PostgreSQL protects the same invariants with row locks instead: the shared
// code calls the Lock* queries, which are plain reads here and SELECT … FOR
// UPDATE there, and its locks type holds no mutex at all.
type locks struct {
	writeMu sync.Mutex
}

// write acquires the mutation mutex and returns its release function, so a
// mutation serializes itself with "defer s.locks.write()()".
func (l *locks) write() func() {
	l.writeMu.Lock()
	return l.writeMu.Unlock
}

// Tx is the SQLite transaction capability exposed only during a Credbound
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

// Kind reports credbound.StoreSQLite.
func (t *Tx) Kind() credbound.StoreKind { return credbound.StoreSQLite }

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

// TxFrom converts a generic Credbound transaction into the live SQLite
// capability. It returns false for another store or an expired callback.
func TxFrom(tx credbound.Tx) (*Tx, bool) {
	handle, ok := tx.(*Tx)
	if !ok || handle.SQL() == nil {
		return nil, false
	}
	return handle, true
}

// sqliteConstraint is the primary result code shared by every constraint
// violation (UNIQUE, PRIMARY KEY, CHECK, FOREIGN KEY, NOT NULL); the extended
// code carries it in its low byte.
const sqliteConstraint = 19

// mapError translates a driver error into the Credbound sentinels. A
// constraint violation is classified by the driver's typed result code rather
// than a message substring, which was locale-fragile and wording-fragile.
func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return credbound.ErrNotFound
	}
	var sqliteErr *sqlitedriver.Error
	if errors.As(err, &sqliteErr) && sqliteErr.Code()&0xff == sqliteConstraint {
		return fmt.Errorf("%w: %v", credbound.ErrConflict, err)
	}
	return err
}

// ctxUnused keeps context imported for the dialect-neutral signatures above.
var _ = context.Background

// SCIM list filters are the one place where the two engines genuinely disagree
// on SQL, so the fragments live here and the builder in scim.go stays shared.
// SQLite compares the TEXT primary key directly and walks a JSON array with
// json_each; PostgreSQL casts its uuid column and uses jsonb_array_elements.
const (
	scimIDFilter    = ` AND id = ?`
	scimEmailFilter = ` AND EXISTS (SELECT 1 FROM json_each(emails_json) e WHERE json_extract(e.value, '$.value') = ?)`
)
