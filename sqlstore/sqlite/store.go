// Package sqlite implements every Credbound persistence port — Store plus
// the optional SessionStore, SignupStore, DomainStore, SCIMStore and
// OAuthStore capabilities — on SQLite through database/sql and
// sqlc-generated queries, committing each mutation's hash-chained audit
// event atomically with the change.
//
// Open the database with the modernc.org/sqlite driver using a DSN that
// carries "_pragma=foreign_keys(1)" and "_texttotime=1" (see New for why
// the store silently relies on both), apply the schema from the module's
// migrations directory, and wire the store into credbound.Config.Store:
//
//	db, err := sql.Open("sqlite", "file:auth.db?_pragma=foreign_keys(1)&_texttotime=1")
//	store, err := sqlite.New(db)
//
// TransactionHook callbacks can regain the raw *sql.Tx through TxFrom to
// append host writes to a Credbound commit.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync/atomic"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
)

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

// Option customizes a Store during New.
type Option func(*Store)

// WithStreamTimeout overrides the 30 second per-query timeout that bounds
// streaming list operations. New rejects non-positive values.
func WithStreamTimeout(timeout time.Duration) Option {
	return func(store *Store) { store.streamTimeout = timeout }
}

// New wraps an already-opened SQLite database. The store issues no PRAGMAs
// itself and silently relies on the connection being opened with the
// modernc.org/sqlite driver and a DSN carrying "_pragma=foreign_keys(1)"
// (referential integrity, which the revocation cascades depend on) and
// "_texttotime=1" (TEXT timestamp scanning):
//
//	sql.Open("sqlite", "file:auth.db?_pragma=foreign_keys(1)&_texttotime=1")
//
// Omitting either parameter corrupts behavior quietly rather than failing
// construction.
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
	return store, nil
}

// Bootstrap atomically creates the first user with its primary email,
// password, workspace, admin membership and root administrator; once the
// instance is populated it reports credbound.ErrConflict.
func (s *Store) Bootstrap(ctx context.Context, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, workspace credbound.Workspace, membership credbound.Membership, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := q.ClaimBootstrap(ctx, commit.Audit.OccurredAt); err != nil {
			return mapError(err)
		}
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, credbound.EmailVerificationCredential{}); err != nil {
			return err
		}
		if err := q.InsertPassword(ctx, db.InsertPasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt}); err != nil {
			return mapError(err)
		}
		if err := q.InsertWorkspace(ctx, db.InsertWorkspaceParams{ID: workspace.ID, Name: workspace.Name, CreatedAt: workspace.CreatedAt, UpdatedAt: workspace.UpdatedAt, DisabledAt: nullableTime(workspace.DisabledAt), RequireMfa: boolValue(workspace.RequireMFA)}); err != nil {
			return mapError(err)
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		return upsertAdmin(ctx, q, admin)
	})
}

// CreateUser inserts a user with a primary email, password credential and
// initial membership in an existing workspace; a duplicate user ID or email
// address reports credbound.ErrConflict.
func (s *Store) CreateUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, membership credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, credbound.EmailVerificationCredential{}); err != nil {
			return err
		}
		if err := q.InsertPassword(ctx, db.InsertPasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt}); err != nil {
			return mapError(err)
		}
		return upsertMembership(ctx, q, membership)
	})
}

// CreateSignup atomically creates a self-service user, its primary email
// (with the optional pending verification), password credential and fresh
// workspace; an unverified address stays excluded from sign-in lookup until
// VerifyEmail.
func (s *Store) CreateSignup(ctx context.Context, user credbound.User, email credbound.EmailAddress, verification *credbound.EmailVerificationCredential, password credbound.PasswordCredential, workspace credbound.Workspace, membership credbound.Membership, commit credbound.Commit) error {
	pending := credbound.EmailVerificationCredential{}
	if verification != nil {
		pending = *verification
	}
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, pending); err != nil {
			return err
		}
		if err := q.InsertPassword(ctx, db.InsertPasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt}); err != nil {
			return mapError(err)
		}
		if err := q.InsertWorkspace(ctx, db.InsertWorkspaceParams{ID: workspace.ID, Name: workspace.Name, CreatedAt: workspace.CreatedAt, UpdatedAt: workspace.UpdatedAt, DisabledAt: nullableTime(workspace.DisabledAt), RequireMfa: boolValue(workspace.RequireMFA)}); err != nil {
			return mapError(err)
		}
		return upsertMembership(ctx, q, membership)
	})
}

// UserByEmail resolves a user by verified email address.
func (s *Store) UserByEmail(ctx context.Context, email string) (credbound.User, error) {
	row, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return credbound.User{}, mapError(err)
	}
	return userFromEmailRow(row), nil
}

// UserByID returns the user with the given ID.
func (s *Store) UserByID(ctx context.Context, id string) (credbound.User, error) {
	row, err := s.queries.GetUserByID(ctx, id)
	if err != nil {
		return credbound.User{}, mapError(err)
	}
	return userFromIDRow(row), nil
}

// SetUserDisabled enables or disables a user; disabling refuses to orphan
// the last enabled root administrator or a workspace's last active admin
// (credbound.ErrConflict) and revokes the user's tokens and sessions.
func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabled bool, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		_, err := q.GetUserByID(ctx, userID)
		if err != nil {
			return mapError(err)
		}
		if disabled {
			admin, adminErr := q.GetInstanceAdministrator(ctx, userID)
			if adminErr != nil && !errors.Is(adminErr, sql.ErrNoRows) {
				return mapError(adminErr)
			}
			if adminErr == nil && admin.Role == string(credbound.InstanceRoleRoot) {
				count, err := q.CountEnabledRootAdministrators(ctx)
				if err != nil {
					return mapError(err)
				}
				if count <= 1 {
					return credbound.ErrConflict
				}
			}
			orphaned, err := q.CountWorkspacesOrphanedByUserDisable(ctx, userID)
			if err != nil {
				return mapError(err)
			}
			if orphaned > 0 {
				return credbound.ErrConflict
			}
		}
		disabledValue := int64(0)
		if disabled {
			disabledValue = 1
		}
		count, err := q.SetUserDisabled(ctx, db.SetUserDisabledParams{ID: userID, Disabled: disabledValue, UpdatedAt: at})
		if err := affected(count, err); err != nil {
			return err
		}
		if disabled {
			if err := q.RevokeUserPATs(ctx, db.RevokeUserPATsParams{UserID: userID, RevokedAt: nullableTime(&at)}); err != nil {
				return mapError(err)
			}
			return mapError(q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID, RevokedAt: nullableTime(&at)}))
		}
		return nil
	})
}

// Users streams all users, newest first, as one cursor page.
func (s *Store) Users(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.User], error] {
	return func(yield func(credbound.PageEvent[credbound.User], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.User]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT u.id, e.address, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound_users u
JOIN credbound_user_emails e ON e.user_id = u.id AND e.is_primary = 1
WHERE (? = '' OR u.created_at < ? OR (u.created_at = ? AND u.id < ?))
ORDER BY u.created_at DESC, u.id DESC LIMIT ?`, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.User]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.User
		count := 0
		for rows.Next() {
			var value credbound.User
			var disabled int64
			var seen sql.NullTime
			if err := rows.Scan(&value.ID, &value.Email, &value.DisplayName, &disabled, &seen, &value.CreatedAt, &value.UpdatedAt); err != nil {
				yield(credbound.PageEvent[credbound.User]{}, err)
				return
			}
			value.Disabled, value.LastSeenAt = disabled == 1, timePointer(seen)
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.User](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.User]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.User](credbound.PageEnd{}), nil)
	}
}

// PasswordByUserID returns the user's stored password credential.
func (s *Store) PasswordByUserID(ctx context.Context, userID string) (credbound.PasswordCredential, error) {
	row, err := s.queries.GetPassword(ctx, userID)
	if err != nil {
		return credbound.PasswordCredential{}, mapError(err)
	}
	return credbound.PasswordCredential{UserID: row.UserID, Hash: row.Hash, UpdatedAt: row.UpdatedAt}, nil
}

// ReplacePassword swaps the user's password credential.
func (s *Store) ReplacePassword(ctx context.Context, password credbound.PasswordCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.ReplacePassword(ctx, db.ReplacePasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt})
		return affected(count, err)
	})
}

// LoginThrottleByUserID returns the user's current login throttle state.
func (s *Store) LoginThrottleByUserID(ctx context.Context, userID string) (credbound.LoginThrottle, error) {
	row, err := s.queries.GetLoginThrottle(ctx, userID)
	if err != nil {
		return credbound.LoginThrottle{}, mapError(err)
	}
	return credbound.LoginThrottle{
		UserID: row.UserID, FailedAttempts: row.FailedAttempts,
		LockedUntil: timePointer(row.LockedUntil), UpdatedAt: row.UpdatedAt,
	}, nil
}

// RecordLoginFailure counts a failed login (restarting the window after an
// expired lockout) and applies lockedUntil once the failure threshold is
// reached, returning the updated throttle.
func (s *Store) RecordLoginFailure(ctx context.Context, userID string, at time.Time, threshold int64, lockedUntil time.Time, commit credbound.Commit) (credbound.LoginThrottle, error) {
	result := credbound.LoginThrottle{UserID: userID, UpdatedAt: at}
	err := s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, userID); err != nil {
			return mapError(err)
		}
		current, currentErr := q.GetLoginThrottle(ctx, userID)
		if currentErr != nil && !errors.Is(currentErr, sql.ErrNoRows) {
			return mapError(currentErr)
		}
		if currentErr == nil && current.LockedUntil.Valid && !at.Before(current.LockedUntil.Time) {
			// The previous lockout has expired: the failure window restarts.
			if err := q.ClearLoginThrottle(ctx, userID); err != nil {
				return mapError(err)
			}
		}
		attempts, err := q.UpsertLoginFailure(ctx, db.UpsertLoginFailureParams{UserID: userID, UpdatedAt: at})
		if err != nil {
			return mapError(err)
		}
		result.FailedAttempts = attempts
		if threshold > 0 && attempts >= threshold {
			count, err := q.LockLoginThrottle(ctx, db.LockLoginThrottleParams{UserID: userID, LockedUntil: nullableTime(&lockedUntil)})
			if err := affected(count, err); err != nil {
				return err
			}
			deadline := lockedUntil
			result.LockedUntil = &deadline
		}
		return nil
	})
	if err != nil {
		return credbound.LoginThrottle{}, err
	}
	return result, nil
}

// RecordAuthentication marks a successful login, updating the user's last-
// seen time and clearing any login throttle.
func (s *Store) RecordAuthentication(ctx context.Context, userID string, seenAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&seenAt)})
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.ClearLoginThrottle(ctx, userID))
	})
}

// CreatePasswordReset stores a single-use password reset credential.
func (s *Store) CreatePasswordReset(ctx context.Context, credential credbound.PasswordResetCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, credential.UserID); err != nil {
			return mapError(err)
		}
		return mapError(q.InsertPasswordReset(ctx, db.InsertPasswordResetParams{
			ID: credential.ID, UserID: credential.UserID, Digest: credential.Digest,
			CreatedAt: credential.CreatedAt, ExpiresAt: credential.ExpiresAt,
		}))
	})
}

// PasswordResetByID returns the password reset credential with the given ID.
func (s *Store) PasswordResetByID(ctx context.Context, resetID string) (credbound.PasswordResetCredential, error) {
	row, err := s.queries.GetPasswordReset(ctx, resetID)
	if err != nil {
		return credbound.PasswordResetCredential{}, mapError(err)
	}
	return credbound.PasswordResetCredential{
		ID: row.ID, UserID: row.UserID, Digest: row.Digest,
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, UsedAt: timePointer(row.UsedAt),
	}, nil
}

// CompletePasswordReset consumes the reset and installs the new password,
// revoking the user's other pending resets, tokens, sessions and throttle in
// the same commit; a reused reset reports credbound.ErrConflict.
func (s *Store) CompletePasswordReset(ctx context.Context, resetID string, password credbound.PasswordCredential, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.ConsumePasswordReset(ctx, db.ConsumePasswordResetParams{ID: resetID, UsedAt: nullableTime(&at)})
		if err != nil {
			return mapError(err)
		}
		if count != 1 {
			return credbound.ErrConflict
		}
		if err := q.DeleteOtherPasswordResets(ctx, db.DeleteOtherPasswordResetsParams{UserID: password.UserID, ID: resetID}); err != nil {
			return mapError(err)
		}
		replaced, err := q.ReplacePassword(ctx, db.ReplacePasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt})
		if err := affected(replaced, err); err != nil {
			return err
		}
		if err := q.RevokeUserPATs(ctx, db.RevokeUserPATsParams{UserID: password.UserID, RevokedAt: nullableTime(&at)}); err != nil {
			return mapError(err)
		}
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: password.UserID, RevokedAt: nullableTime(&at)}); err != nil {
			return mapError(err)
		}
		if err := s.revokeOAuthGrants(ctx, q, at, func(grant credbound.OAuthGrant) bool { return grant.UserID == password.UserID }); err != nil {
			return err
		}
		return mapError(q.ClearLoginThrottle(ctx, password.UserID))
	})
}

// CreateEmailAuthentication stores a single-use magic-link or email OTP
// credential.
func (s *Store) CreateEmailAuthentication(ctx context.Context, credential credbound.EmailAuthenticationCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, credential.UserID); err != nil {
			return mapError(err)
		}
		return mapError(q.InsertEmailAuthentication(ctx, db.InsertEmailAuthenticationParams{
			ID: credential.ID, UserID: credential.UserID, EmailID: credential.EmailID,
			Digest: credential.Digest, CreatedAt: credential.CreatedAt, ExpiresAt: credential.ExpiresAt,
		}))
	})
}

// EmailAuthenticationByID returns the email authentication credential with
// the given token ID.
func (s *Store) EmailAuthenticationByID(ctx context.Context, tokenID string) (credbound.EmailAuthenticationCredential, error) {
	row, err := s.queries.GetEmailAuthentication(ctx, tokenID)
	if err != nil {
		return credbound.EmailAuthenticationCredential{}, mapError(err)
	}
	return credbound.EmailAuthenticationCredential{
		ID: row.ID, UserID: row.UserID, EmailID: row.EmailID, Digest: row.Digest,
		CreatedAt: row.CreatedAt, ExpiresAt: row.ExpiresAt, UsedAt: timePointer(row.UsedAt),
	}, nil
}

// ConsumeEmailAuthentication marks the user's credential used, updating
// last-seen and clearing the login throttle; reuse reports
// credbound.ErrConflict.
func (s *Store) ConsumeEmailAuthentication(ctx context.Context, tokenID, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.ConsumeEmailAuthentication(ctx, db.ConsumeEmailAuthenticationParams{ID: tokenID, UserID: userID, UsedAt: nullableTime(&at)})
		if err != nil {
			return mapError(err)
		}
		if count != 1 {
			return credbound.ErrConflict
		}
		touched, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&at)})
		if err := affected(touched, err); err != nil {
			return err
		}
		return mapError(q.ClearLoginThrottle(ctx, userID))
	})
}

// SaveEmail adds an additional email address with its pending verification
// credential; a duplicate address reports credbound.ErrConflict.
func (s *Store) SaveEmail(ctx context.Context, email credbound.EmailAddress, verification credbound.EmailVerificationCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error { return insertEmail(ctx, q, email, verification) })
}

// EmailVerificationByID returns the email address and its pending
// verification credential.
func (s *Store) EmailVerificationByID(ctx context.Context, emailID string) (credbound.EmailAddress, credbound.EmailVerificationCredential, error) {
	row, err := s.queries.GetEmailVerification(ctx, emailID)
	if err != nil {
		return credbound.EmailAddress{}, credbound.EmailVerificationCredential{}, mapError(err)
	}
	return emailFromRow(row), credbound.EmailVerificationCredential{
		EmailID: row.ID, Digest: row.VerificationDigest, ExpiresAt: row.VerificationExpiresAt.Time,
	}, nil
}

// VerifyEmail marks the address verified, makes it usable for sign-in and
// discards the verification credential; an already-verified address reports
// credbound.ErrConflict.
func (s *Store) VerifyEmail(ctx context.Context, emailID string, verifiedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.VerifyEmail(ctx, db.VerifyEmailParams{ID: emailID, VerifiedAt: nullableTime(&verifiedAt)})
		return affected(count, err)
	})
}

// SetPrimaryEmail promotes a verified address to primary and demotes the
// previous one; an unverified target reports credbound.ErrConflict.
func (s *Store) SetPrimaryEmail(ctx context.Context, userID, emailID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		email, err := q.GetEmailVerification(ctx, emailID)
		if err != nil {
			return mapError(err)
		}
		if email.UserID != userID || !email.VerifiedAt.Valid {
			return credbound.ErrNotFound
		}
		if err := q.ClearPrimaryEmails(ctx, db.ClearPrimaryEmailsParams{UserID: userID, UpdatedAt: commit.Audit.OccurredAt}); err != nil {
			return mapError(err)
		}
		count, err := q.SetPrimaryEmail(ctx, db.SetPrimaryEmailParams{UserID: userID, ID: emailID, UpdatedAt: commit.Audit.OccurredAt})
		return affected(count, err)
	})
}

// RemoveEmail deletes a non-primary address, refusing to remove the user's
// last verified one (credbound.ErrConflict).
func (s *Store) RemoveEmail(ctx context.Context, userID, emailID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		email, err := q.GetEmailVerification(ctx, emailID)
		if err != nil {
			return mapError(err)
		}
		if email.UserID != userID {
			return credbound.ErrNotFound
		}
		if email.IsPrimary == 1 {
			return credbound.ErrConflict
		}
		if email.VerifiedAt.Valid {
			count, err := q.CountVerifiedEmails(ctx, userID)
			if err != nil {
				return mapError(err)
			}
			if count <= 1 {
				return credbound.ErrConflict
			}
		}
		count, err := q.DeleteEmail(ctx, db.DeleteEmailParams{UserID: userID, ID: emailID})
		return affected(count, err)
	})
}

// Emails streams the user's email addresses, newest first, as one cursor
// page.
func (s *Store) Emails(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.EmailAddress], error] {
	return func(yield func(credbound.PageEvent[credbound.EmailAddress], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, user_id, address, is_primary, verified_at, created_at, updated_at
FROM credbound_user_emails
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.EmailAddress
		count := 0
		for rows.Next() {
			var value credbound.EmailAddress
			var primary int64
			var verified sql.NullTime
			if err := rows.Scan(&value.ID, &value.UserID, &value.Address, &primary, &verified, &value.CreatedAt, &value.UpdatedAt); err != nil {
				yield(credbound.PageEvent[credbound.EmailAddress]{}, err)
				return
			}
			value.Primary, value.VerifiedAt = primary == 1, timePointer(verified)
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.EmailAddress](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.EmailAddress](credbound.PageEnd{}), nil)
	}
}

// TOTPByUserID returns the user's TOTP factor.
func (s *Store) TOTPByUserID(ctx context.Context, userID string) (credbound.TOTPFactor, error) {
	row, err := s.queries.GetTOTP(ctx, userID)
	if err != nil {
		return credbound.TOTPFactor{}, mapError(err)
	}
	return credbound.TOTPFactor{
		UserID: row.UserID, EncryptedSecret: row.EncryptedSecret, Active: row.Active == 1,
		LastUsedStep: row.LastUsedStep, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// SaveTOTPEnrollment stores a pending TOTP factor, replacing any prior
// pending enrollment; an already-active factor reports
// credbound.ErrConflict.
func (s *Store) SaveTOTPEnrollment(ctx context.Context, factor credbound.TOTPFactor, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.SaveTOTPEnrollment(ctx, db.SaveTOTPEnrollmentParams{
			UserID: factor.UserID, EncryptedSecret: factor.EncryptedSecret,
			CreatedAt: factor.CreatedAt, UpdatedAt: factor.UpdatedAt,
		})
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.DeleteRecoveryCodes(ctx, factor.UserID))
	})
}

// ActivateTOTP activates the pending factor and stores its recovery codes in
// the same commit.
func (s *Store) ActivateTOTP(ctx context.Context, factor credbound.TOTPFactor, recovery []credbound.RecoveryCode, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.ActivateTOTP(ctx, db.ActivateTOTPParams{
			UserID: factor.UserID, EncryptedSecret: factor.EncryptedSecret,
			LastUsedStep: factor.LastUsedStep, UpdatedAt: factor.UpdatedAt,
		})
		if err := affected(count, err); err != nil {
			return err
		}
		if err := q.DeleteRecoveryCodes(ctx, factor.UserID); err != nil {
			return mapError(err)
		}
		for _, code := range recovery {
			if err := q.InsertRecoveryCode(ctx, db.InsertRecoveryCodeParams{UserID: code.UserID, Digest: code.Digest}); err != nil {
				return mapError(err)
			}
		}
		return nil
	})
}

// UseTOTP records a successful code for the given time step, reporting false
// without error when the step was already consumed (replay).
func (s *Store) UseTOTP(ctx context.Context, userID string, step int64, commit credbound.Commit) (bool, error) {
	used := false
	err := s.mutateIf(ctx, commit, func(q *db.Queries) (bool, error) {
		count, err := q.UseTOTP(ctx, db.UseTOTPParams{UserID: userID, LastUsedStep: step, UpdatedAt: commit.Audit.OccurredAt})
		if err != nil {
			return false, mapError(err)
		}
		used = count == 1
		if used {
			if _, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&commit.Audit.OccurredAt)}); err != nil {
				return false, mapError(err)
			}
			if err := q.ClearLoginThrottle(ctx, userID); err != nil {
				return false, mapError(err)
			}
		}
		return used, nil
	})
	return used, err
}

// ConsumeRecoveryCode marks the matching unused recovery code used,
// reporting false when no unused code matches the digest.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID string, digest []byte, usedAt time.Time, commit credbound.Commit) (bool, error) {
	used := false
	err := s.mutateIf(ctx, commit, func(q *db.Queries) (bool, error) {
		count, err := q.ConsumeRecoveryCode(ctx, db.ConsumeRecoveryCodeParams{UserID: userID, Digest: digest, UsedAt: nullableTime(&usedAt)})
		if err != nil {
			return false, mapError(err)
		}
		used = count == 1
		if used {
			if _, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&usedAt)}); err != nil {
				return false, mapError(err)
			}
			if err := q.ClearLoginThrottle(ctx, userID); err != nil {
				return false, mapError(err)
			}
		}
		return used, nil
	})
	return used, err
}

// CountUnusedRecoveryCodes reports how many of the user's recovery codes
// remain unused.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int64, error) {
	count, err := s.queries.CountUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		return 0, mapError(err)
	}
	return count, nil
}

// DisableTOTP removes the user's TOTP factor and recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteTOTP(ctx, userID)
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.DeleteRecoveryCodes(ctx, userID))
	})
}

// Passkeys streams the user's passkeys in creation order.
func (s *Store) Passkeys(ctx context.Context, userID string) iter.Seq2[credbound.Passkey, error] {
	return func(yield func(credbound.Passkey, error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, user_id, name, credential_id, credential_json, created_at, last_used_at
FROM credbound_passkeys WHERE user_id = ? ORDER BY created_at, id`, userID)
		if err != nil {
			yield(credbound.Passkey{}, mapError(err))
			return
		}
		defer rows.Close()
		for rows.Next() {
			var value credbound.Passkey
			var last sql.NullTime
			if err := rows.Scan(&value.ID, &value.UserID, &value.Name, &value.CredentialID, &value.CredentialJSON, &value.CreatedAt, &last); err != nil {
				yield(credbound.Passkey{}, err)
				return
			}
			value.LastUsedAt = timePointer(last)
			if !yield(value, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.Passkey{}, err)
		}
	}
}

// SavePasskey stores a new passkey; a credential ID already registered to
// any user reports credbound.ErrConflict.
func (s *Store) SavePasskey(ctx context.Context, passkey credbound.Passkey, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		return mapError(q.InsertPasskey(ctx, db.InsertPasskeyParams{
			ID: passkey.ID, UserID: passkey.UserID, Name: passkey.Name,
			CredentialID: passkey.CredentialID, CredentialJson: passkey.CredentialJSON, CreatedAt: passkey.CreatedAt,
		}))
	})
}

// TouchPasskey persists the credential's updated JSON (sign counter) and
// last-used time after a successful assertion.
func (s *Store) TouchPasskey(ctx context.Context, userID string, credentialID, credentialJSON []byte, usedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchPasskey(ctx, db.TouchPasskeyParams{
			UserID: userID, CredentialID: credentialID, CredentialJson: credentialJSON, LastUsedAt: nullableTime(&usedAt),
		})
		if err := affected(count, err); err != nil {
			return err
		}
		count, err = q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&usedAt)})
		return affected(count, err)
	})
}

// DeletePasskey removes one of the user's passkeys.
func (s *Store) DeletePasskey(ctx context.Context, userID, passkeyID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeletePasskey(ctx, db.DeletePasskeyParams{UserID: userID, ID: passkeyID})
		return affected(count, err)
	})
}

// CreatePAT stores a personal access token record; a duplicate ID or prefix
// reports credbound.ErrConflict.
func (s *Store) CreatePAT(ctx context.Context, pat credbound.PAT, commit credbound.Commit) error {
	scopes, err := json.Marshal(pat.Scopes)
	if err != nil {
		return err
	}
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		return mapError(q.InsertPAT(ctx, db.InsertPATParams{
			ID: pat.ID, UserID: pat.UserID, Name: pat.Name, Prefix: pat.Prefix, Digest: pat.Digest,
			WorkspaceID: nullableString(pat.WorkspaceID), ScopesJson: string(scopes), CreatedAt: pat.CreatedAt, ExpiresAt: nullableTime(pat.ExpiresAt),
		}))
	})
}

// PATByPrefix returns the token record addressed by its lookup prefix.
func (s *Store) PATByPrefix(ctx context.Context, prefix string) (credbound.PAT, error) {
	row, err := s.queries.GetPATByPrefix(ctx, prefix)
	if err != nil {
		return credbound.PAT{}, mapError(err)
	}
	return patFromRow(row)
}

// TouchPAT records a token use, updating the token's and user's last-seen
// times.
func (s *Store) TouchPAT(ctx context.Context, id string, usedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		pat, err := q.GetPATByID(ctx, id)
		if err != nil {
			return mapError(err)
		}
		count, err := q.TouchPAT(ctx, db.TouchPATParams{ID: id, LastUsedAt: nullableTime(&usedAt)})
		if err := affected(count, err); err != nil {
			return err
		}
		count, err = q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: pat.UserID, LastSeenAt: nullableTime(&usedAt)})
		return affected(count, err)
	})
}

// RevokePAT marks the user's token revoked.
func (s *Store) RevokePAT(ctx context.Context, userID, id string, revokedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.RevokePAT(ctx, db.RevokePATParams{UserID: userID, ID: id, RevokedAt: nullableTime(&revokedAt)})
		return affected(count, err)
	})
}

// RevokeUserCredentials revokes all of the user's tokens (PATs and OAuth)
// and sessions in one commit.
func (s *Store) RevokeUserCredentials(ctx context.Context, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetUserByID(ctx, userID); err != nil {
			return mapError(err)
		}
		if err := q.RevokeUserPATs(ctx, db.RevokeUserPATsParams{UserID: userID, RevokedAt: nullableTime(&at)}); err != nil {
			return mapError(err)
		}
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: userID, RevokedAt: nullableTime(&at)}); err != nil {
			return mapError(err)
		}
		return s.revokeOAuthGrants(ctx, q, at, func(grant credbound.OAuthGrant) bool { return grant.UserID == userID })
	})
}

// PATs streams the user's tokens, newest first, as one cursor page with
// digests omitted.
func (s *Store) PATs(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.PAT], error] {
	return func(yield func(credbound.PageEvent[credbound.PAT], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.PAT]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound_personal_access_tokens
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.PAT]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.PAT
		count := 0
		for rows.Next() {
			value, err := scanPAT(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.PAT]{}, err)
				return
			}
			if count == page.Limit {
				end := credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}
				yield(credbound.EndEvent[credbound.PAT](end), nil)
				return
			}
			value.Digest = nil
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.PAT]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.PAT](credbound.PageEnd{}), nil)
	}
}

// CreateWorkspaceInvitation stores an invitation; a pending invitation for
// the same address in the workspace reports credbound.ErrConflict.
func (s *Store) CreateWorkspaceInvitation(ctx context.Context, invitation credbound.WorkspaceInvitation, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		return mapError(q.InsertWorkspaceInvitation(ctx, db.InsertWorkspaceInvitationParams{
			ID: invitation.ID, WorkspaceID: invitation.WorkspaceID, Email: invitation.Email,
			Role: string(invitation.Role), InvitedBy: invitation.InvitedBy, Digest: invitation.Digest,
			CreatedAt: invitation.CreatedAt, ExpiresAt: invitation.ExpiresAt,
		}))
	})
}

// WorkspaceInvitationByID returns the invitation with the given ID.
func (s *Store) WorkspaceInvitationByID(ctx context.Context, invitationID string) (credbound.WorkspaceInvitation, error) {
	row, err := s.queries.GetWorkspaceInvitation(ctx, invitationID)
	if err != nil {
		return credbound.WorkspaceInvitation{}, mapError(err)
	}
	return invitationFromRow(row.ID, row.WorkspaceID, row.Email, row.Role, row.InvitedBy, row.Digest, row.CreatedAt, row.ExpiresAt, row.AcceptedAt, row.AcceptedUserID, row.RevokedAt), nil
}

// PendingWorkspaceInvitation returns the workspace's unaccepted, unrevoked
// invitation for the email address.
func (s *Store) PendingWorkspaceInvitation(ctx context.Context, workspaceID, email string) (credbound.WorkspaceInvitation, error) {
	row, err := s.queries.GetPendingWorkspaceInvitation(ctx, db.GetPendingWorkspaceInvitationParams{WorkspaceID: workspaceID, Email: email})
	if err != nil {
		return credbound.WorkspaceInvitation{}, mapError(err)
	}
	return invitationFromRow(row.ID, row.WorkspaceID, row.Email, row.Role, row.InvitedBy, row.Digest, row.CreatedAt, row.ExpiresAt, row.AcceptedAt, row.AcceptedUserID, row.RevokedAt), nil
}

// AcceptWorkspaceInvitation marks the invitation accepted by the user and
// installs the resulting membership in the same commit; an accepted or
// revoked invitation reports credbound.ErrConflict.
func (s *Store) AcceptWorkspaceInvitation(ctx context.Context, invitationID, userID string, at time.Time, membership credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.AcceptWorkspaceInvitation(ctx, db.AcceptWorkspaceInvitationParams{ID: invitationID, AcceptedAt: nullableTime(&at), AcceptedUserID: nullableString(userID)})
		if err != nil {
			return mapError(err)
		}
		if count != 1 {
			return credbound.ErrConflict
		}
		return upsertMembership(ctx, q, membership)
	})
}

// RegisterInvitedUser atomically creates the invited user with email,
// password and membership while accepting the invitation.
func (s *Store) RegisterInvitedUser(ctx context.Context, invitationID string, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, membership credbound.Membership, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.AcceptWorkspaceInvitation(ctx, db.AcceptWorkspaceInvitationParams{ID: invitationID, AcceptedAt: nullableTime(&at), AcceptedUserID: nullableString(user.ID)})
		if err != nil {
			return mapError(err)
		}
		if count != 1 {
			return credbound.ErrConflict
		}
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, credbound.EmailVerificationCredential{}); err != nil {
			return err
		}
		if err := q.InsertPassword(ctx, db.InsertPasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt}); err != nil {
			return mapError(err)
		}
		return upsertMembership(ctx, q, membership)
	})
}

// RevokeWorkspaceInvitation marks the workspace's invitation revoked; an
// accepted or already-revoked invitation reports credbound.ErrConflict.
func (s *Store) RevokeWorkspaceInvitation(ctx context.Context, workspaceID, invitationID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.RevokeWorkspaceInvitation(ctx, db.RevokeWorkspaceInvitationParams{WorkspaceID: workspaceID, ID: invitationID, RevokedAt: nullableTime(&at)})
		if err != nil {
			return mapError(err)
		}
		if count != 1 {
			return credbound.ErrConflict
		}
		return nil
	})
}

// WorkspaceInvitations streams the workspace's invitations, newest first, as
// one cursor page.
func (s *Store) WorkspaceInvitations(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.WorkspaceInvitation], error] {
	return func(yield func(credbound.PageEvent[credbound.WorkspaceInvitation], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound_workspace_invitations
WHERE workspace_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, workspaceID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.WorkspaceInvitation
		count := 0
		for rows.Next() {
			var value credbound.WorkspaceInvitation
			var role string
			var accepted, revoked sql.NullTime
			var acceptedUser sql.NullString
			if err := rows.Scan(&value.ID, &value.WorkspaceID, &value.Email, &role, &value.InvitedBy, &value.Digest, &value.CreatedAt, &value.ExpiresAt, &accepted, &acceptedUser, &revoked); err != nil {
				yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, err)
				return
			}
			value.Role = credbound.Role(role)
			value.AcceptedAt, value.RevokedAt = timePointer(accepted), timePointer(revoked)
			value.AcceptedUserID = acceptedUser.String
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.WorkspaceInvitation](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.WorkspaceInvitation](credbound.PageEnd{}), nil)
	}
}

func invitationFromRow(id, workspaceID, email, role, invitedBy string, digestValue []byte, createdAt, expiresAt time.Time, acceptedAt sql.NullTime, acceptedUserID sql.NullString, revokedAt sql.NullTime) credbound.WorkspaceInvitation {
	return credbound.WorkspaceInvitation{
		ID: id, WorkspaceID: workspaceID, Email: email, Role: credbound.Role(role), InvitedBy: invitedBy,
		Digest: digestValue, CreatedAt: createdAt, ExpiresAt: expiresAt,
		AcceptedAt: timePointer(acceptedAt), AcceptedUserID: acceptedUserID.String, RevokedAt: timePointer(revokedAt),
	}
}

// CreateWorkspace inserts a workspace together with its owning membership.
func (s *Store) CreateWorkspace(ctx context.Context, workspace credbound.Workspace, owner credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := q.InsertWorkspace(ctx, db.InsertWorkspaceParams{
			ID: workspace.ID, Name: workspace.Name, CreatedAt: workspace.CreatedAt,
			UpdatedAt: workspace.UpdatedAt, DisabledAt: nullableTime(workspace.DisabledAt),
			RequireMfa: boolValue(workspace.RequireMFA),
		}); err != nil {
			return mapError(err)
		}
		return upsertMembership(ctx, q, owner)
	})
}

// WorkspaceByID returns the workspace with the given ID.
func (s *Store) WorkspaceByID(ctx context.Context, workspaceID string) (credbound.Workspace, error) {
	row, err := s.queries.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return credbound.Workspace{}, mapError(err)
	}
	return workspaceFromRow(row), nil
}

// UpdateWorkspace persists the workspace's mutable attributes.
func (s *Store) UpdateWorkspace(ctx context.Context, workspace credbound.Workspace, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.UpdateWorkspace(ctx, db.UpdateWorkspaceParams{ID: workspace.ID, Name: workspace.Name, UpdatedAt: workspace.UpdatedAt, RequireMfa: boolValue(workspace.RequireMFA)})
		return affected(count, err)
	})
}

// SetWorkspaceDisabled enables or disables the workspace; disabling revokes
// the members' workspace-scoped tokens.
func (s *Store) SetWorkspaceDisabled(ctx context.Context, workspaceID string, disabled bool, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		var disabledAt *time.Time
		if disabled {
			disabledAt = &at
		}
		count, err := q.SetWorkspaceDisabled(ctx, db.SetWorkspaceDisabledParams{ID: workspaceID, DisabledAt: nullableTime(disabledAt), UpdatedAt: at})
		if err := affected(count, err); err != nil {
			return err
		}
		if disabled {
			return mapError(q.RevokeAllWorkspacePATs(ctx, db.RevokeAllWorkspacePATsParams{WorkspaceID: nullableString(workspaceID), RevokedAt: nullableTime(&at)}))
		}
		return nil
	})
}

// Workspaces streams all workspaces, newest first, as one cursor page.
func (s *Store) Workspaces(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return s.workspaces(ctx, "", page)
}

// UserWorkspaces streams the workspaces the user belongs to, newest first,
// as one cursor page.
func (s *Store) UserWorkspaces(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return s.workspaces(ctx, userID, page)
}

func (s *Store) workspaces(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return func(yield func(credbound.PageEvent[credbound.Workspace], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Workspace]{}, err)
			return
		}
		query := `SELECT w.id, w.name, w.created_at, w.updated_at, w.disabled_at, w.require_mfa
FROM credbound_workspaces w
WHERE (? = '' OR EXISTS (SELECT 1 FROM credbound_memberships m WHERE m.workspace_id = w.id AND m.user_id = ?))
AND (? = '' OR w.created_at < ? OR (w.created_at = ? AND w.id < ?))
ORDER BY w.created_at DESC, w.id DESC LIMIT ?`
		rows, err := s.db.QueryContext(streamCtx, query, userID, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.Workspace]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.Workspace
		count := 0
		for rows.Next() {
			var value credbound.Workspace
			var disabled sql.NullTime
			var requireMFA int64
			if err := rows.Scan(&value.ID, &value.Name, &value.CreatedAt, &value.UpdatedAt, &disabled, &requireMFA); err != nil {
				yield(credbound.PageEvent[credbound.Workspace]{}, err)
				return
			}
			value.DisabledAt, value.RequireMFA = timePointer(disabled), requireMFA == 1
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.Workspace](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Workspace]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.Workspace](credbound.PageEnd{}), nil)
	}
}

// Membership returns the user's membership in the workspace.
func (s *Store) Membership(ctx context.Context, workspaceID, userID string) (credbound.Membership, error) {
	row, err := s.queries.GetMembership(ctx, db.GetMembershipParams{WorkspaceID: workspaceID, UserID: userID})
	if err != nil {
		return credbound.Membership{}, mapError(err)
	}
	return credbound.Membership{
		WorkspaceID: row.WorkspaceID, UserID: row.UserID, Role: credbound.Role(row.Role),
		Status: credbound.MembershipStatus(row.Status), ProvisioningSource: row.ProvisioningSource,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}, nil
}

// UpsertMembership inserts or updates a membership, refusing a change that
// would leave the workspace without an active admin (credbound.ErrConflict);
// deactivation revokes the member's workspace-scoped tokens.
func (s *Store) UpsertMembership(ctx context.Context, membership credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetMembership(ctx, db.GetMembershipParams{WorkspaceID: membership.WorkspaceID, UserID: membership.UserID})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return mapError(err)
		}
		if err == nil && current.Role == string(credbound.RoleAdmin) && current.Status == string(credbound.MembershipActive) &&
			(membership.Role != credbound.RoleAdmin || membership.Status != credbound.MembershipActive) {
			count, err := q.CountActiveWorkspaceAdministrators(ctx, membership.WorkspaceID)
			if err != nil {
				return mapError(err)
			}
			if count <= 1 {
				return credbound.ErrConflict
			}
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		if membership.Status != credbound.MembershipActive {
			return mapError(q.RevokeWorkspacePATs(ctx, db.RevokeWorkspacePATsParams{
				UserID: membership.UserID, WorkspaceID: nullableString(membership.WorkspaceID), RevokedAt: nullableTime(&commit.Audit.OccurredAt),
			}))
		}
		return nil
	})
}

// RemoveMembership deletes the membership, refusing to remove the
// workspace's last active admin (credbound.ErrConflict) and revoking the
// member's workspace-scoped tokens.
func (s *Store) RemoveMembership(ctx context.Context, workspaceID, userID string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetMembership(ctx, db.GetMembershipParams{WorkspaceID: workspaceID, UserID: userID})
		if err != nil {
			return mapError(err)
		}
		if current.Role == string(credbound.RoleAdmin) && current.Status == string(credbound.MembershipActive) {
			count, err := q.CountActiveWorkspaceAdministrators(ctx, workspaceID)
			if err != nil {
				return mapError(err)
			}
			if count <= 1 {
				return credbound.ErrConflict
			}
		}
		count, err := q.DeleteMembership(ctx, db.DeleteMembershipParams{WorkspaceID: workspaceID, UserID: userID})
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.RevokeWorkspacePATs(ctx, db.RevokeWorkspacePATsParams{
			UserID: userID, WorkspaceID: nullableString(workspaceID), RevokedAt: nullableTime(&at),
		}))
	})
}

// Memberships streams the workspace's memberships, newest first, as one
// cursor page.
func (s *Store) Memberships(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Membership], error] {
	return func(yield func(credbound.PageEvent[credbound.Membership], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Membership]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at
FROM credbound_memberships
WHERE workspace_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND user_id < ?))
ORDER BY created_at DESC, user_id DESC LIMIT ?`, workspaceID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.Membership]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.Membership
		count := 0
		for rows.Next() {
			var value credbound.Membership
			if err := rows.Scan(&value.WorkspaceID, &value.UserID, &value.Role, &value.Status, &value.ProvisioningSource, &value.CreatedAt, &value.UpdatedAt); err != nil {
				yield(credbound.PageEvent[credbound.Membership]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.Membership](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.UserID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Membership]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.Membership](credbound.PageEnd{}), nil)
	}
}

// InstanceAdministrator returns the user's instance-administration role.
func (s *Store) InstanceAdministrator(ctx context.Context, userID string) (credbound.InstanceAdministrator, error) {
	row, err := s.queries.GetInstanceAdministrator(ctx, userID)
	if err != nil {
		return credbound.InstanceAdministrator{}, mapError(err)
	}
	return credbound.InstanceAdministrator{UserID: row.UserID, Role: credbound.InstanceRole(row.Role), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

// SetInstanceRole grants or changes a user's instance role, refusing to
// demote the last root administrator (credbound.ErrConflict).
func (s *Store) SetInstanceRole(ctx context.Context, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		current, err := q.GetInstanceAdministrator(ctx, admin.UserID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return mapError(err)
		}
		if err == nil && current.Role == string(credbound.InstanceRoleRoot) && admin.Role != credbound.InstanceRoleRoot {
			count, err := q.CountRootAdministrators(ctx)
			if err != nil {
				return mapError(err)
			}
			if count <= 1 {
				return credbound.ErrConflict
			}
		}
		return upsertAdmin(ctx, q, admin)
	})
}

// RemoveInstanceRole revokes the user's instance role, refusing to remove
// the last root administrator (credbound.ErrConflict).
func (s *Store) RemoveInstanceRole(ctx context.Context, userID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		admin, err := q.GetInstanceAdministrator(ctx, userID)
		if err != nil {
			return mapError(err)
		}
		if admin.Role == string(credbound.InstanceRoleRoot) {
			count, err := q.CountRootAdministrators(ctx)
			if err != nil {
				return mapError(err)
			}
			if count <= 1 {
				return credbound.ErrConflict
			}
		}
		count, err := q.DeleteInstanceAdministrator(ctx, userID)
		return affected(count, err)
	})
}

// SSOIdentity resolves a linked identity by provider configuration, issuer
// and subject.
func (s *Store) SSOIdentity(ctx context.Context, providerConfigurationID, issuer, subject string) (credbound.SSOIdentity, error) {
	row, err := s.queries.GetSSOIdentity(ctx, db.GetSSOIdentityParams{
		ProviderConfigurationID: providerConfigurationID, Issuer: issuer, Subject: subject,
	})
	if err != nil {
		return credbound.SSOIdentity{}, mapError(err)
	}
	return ssoFromRow(row), nil
}

// LinkSSO stores a new SSO identity link; an identity already linked to any
// user reports credbound.ErrConflict.
func (s *Store) LinkSSO(ctx context.Context, identity credbound.SSOIdentity, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := q.InsertSSOIdentity(ctx, db.InsertSSOIdentityParams{
			ID: identity.ID, UserID: identity.UserID, ProviderConfigurationID: identity.ProviderConfigurationID,
			ProviderKind: string(identity.ProviderKind), Issuer: identity.Issuer, Subject: identity.Subject,
			Email: identity.Email, CreatedAt: identity.CreatedAt, LastUsedAt: nullableTime(identity.LastUsedAt),
		}); err != nil {
			return mapError(err)
		}
		if identity.LastUsedAt != nil {
			count, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: identity.UserID, LastSeenAt: nullableTime(identity.LastUsedAt)})
			return affected(count, err)
		}
		return nil
	})
}

// TouchSSO updates the identity's last-used time and the user's last-seen
// time after a successful SSO login.
func (s *Store) TouchSSO(ctx context.Context, userID, identityID string, usedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchSSOIdentity(ctx, db.TouchSSOIdentityParams{UserID: userID, ID: identityID, LastUsedAt: nullableTime(&usedAt)})
		if err := affected(count, err); err != nil {
			return err
		}
		count, err = q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&usedAt)})
		return affected(count, err)
	})
}

// UnlinkSSO removes the user's SSO identity link.
func (s *Store) UnlinkSSO(ctx context.Context, userID, identityID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteSSOIdentity(ctx, db.DeleteSSOIdentityParams{UserID: userID, ID: identityID})
		return affected(count, err)
	})
}

// SSOIdentities streams the user's SSO identity links, newest first, as one
// cursor page.
func (s *Store) SSOIdentities(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SSOIdentity], error] {
	return func(yield func(credbound.PageEvent[credbound.SSOIdentity], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound_sso_identities
WHERE user_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, userID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.SSOIdentity]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.SSOIdentity
		count := 0
		for rows.Next() {
			var value credbound.SSOIdentity
			var kind string
			var lastUsed sql.NullTime
			if err := rows.Scan(&value.ID, &value.UserID, &value.ProviderConfigurationID, &kind, &value.Issuer, &value.Subject, &value.Email, &value.CreatedAt, &lastUsed); err != nil {
				yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
				return
			}
			value.ProviderKind, value.LastUsedAt = credbound.SSOProviderKind(kind), timePointer(lastUsed)
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.SSOIdentity](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.SSOIdentity](credbound.PageEnd{}), nil)
	}
}

// AppendAudit commits a standalone audit event (and any transactional hook)
// without another mutation.
func (s *Store) AppendAudit(ctx context.Context, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(*db.Queries) error { return nil })
}

// AuditEvents streams the workspace's audit events, newest first, as one
// cursor page.
func (s *Store) AuditEvents(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return s.auditEvents(ctx, page, `workspace_id = ? AND`, []any{workspaceID})
}

// InstanceAuditEvents streams audit events across the whole instance, newest
// first, as one cursor page.
func (s *Store) InstanceAuditEvents(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return s.auditEvents(ctx, page, "", nil)
}

func (s *Store) auditEvents(ctx context.Context, page credbound.PageRequest, filter string, filterArgs []any) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return func(yield func(credbound.PageEvent[credbound.AuditEvent], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		query := `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash
FROM credbound_audit_events
WHERE ` + filter + ` (? = '' OR occurred_at < ? OR (occurred_at = ? AND id < ?))
ORDER BY occurred_at DESC, id DESC LIMIT ?`
		args := append(filterArgs, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		rows, err := s.db.QueryContext(streamCtx, query, args...)
		if err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.AuditEvent
		count := 0
		for rows.Next() {
			value, err := scanAuditEvent(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.AuditEvent](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.OccurredAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.AuditEvent](credbound.PageEnd{}), nil)
	}
}

func (s *Store) mutate(ctx context.Context, commit credbound.Commit, fn func(*db.Queries) error) error {
	return s.mutateIf(ctx, commit, func(q *db.Queries) (bool, error) { return true, fn(q) })
}

func (s *Store) mutateIf(ctx context.Context, commit credbound.Commit, fn func(*db.Queries) (bool, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapError(err)
	}
	defer tx.Rollback()
	q := s.queries.WithTx(tx)
	changed, err := fn(q)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	if commit.Transactional != nil {
		handle := newTx(tx, commit.Audit)
		hookErr := commit.Transactional(ctx, handle)
		handle.close()
		if hookErr != nil {
			return hookErr
		}
	}
	if err := chainAudit(ctx, q, commit.Audit); err != nil {
		return err
	}
	return mapError(tx.Commit())
}

// chainAudit links the audit event to the persisted chain head and appends it
// inside the same transaction as the mutation it records.
func chainAudit(ctx context.Context, q *db.Queries, event credbound.AuditEvent) error {
	if event.ActorKind == "" {
		event.ActorKind = credbound.ActorUser
	}
	head, err := q.GetAuditChainHead(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", credbound.ErrAuditUnavailable, err)
	}
	event.Sequence = head.Sequence + 1
	event.PreviousHash = head.HeadHash
	event.Hash = credbound.ComputeAuditHash(head.HeadHash, event)
	if err := q.InsertAudit(ctx, auditParams(event)); err != nil {
		return fmt.Errorf("%w: %v", credbound.ErrAuditUnavailable, err)
	}
	count, err := q.UpdateAuditChainHead(ctx, db.UpdateAuditChainHeadParams{Sequence: event.Sequence, HeadHash: event.Hash})
	if err != nil || count != 1 {
		return fmt.Errorf("%w: audit chain head update failed: %v", credbound.ErrAuditUnavailable, err)
	}
	return nil
}

// AuditChainHead returns the sequence number and hash of the latest chained
// audit event.
func (s *Store) AuditChainHead(ctx context.Context) (int64, []byte, error) {
	head, err := s.queries.GetAuditChainHead(ctx)
	if err != nil {
		return 0, nil, mapError(err)
	}
	return head.Sequence, head.HeadHash, nil
}

const chainedAuditQuery = `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash
FROM credbound_audit_events WHERE sequence IS NOT NULL ORDER BY sequence`

// ChainedAuditEvents streams every chained audit event in sequence order for
// verification with credbound.VerifyAuditChain.
func (s *Store) ChainedAuditEvents(ctx context.Context) iter.Seq2[credbound.AuditEvent, error] {
	return func(yield func(credbound.AuditEvent, error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		rows, err := s.db.QueryContext(streamCtx, chainedAuditQuery)
		if err != nil {
			yield(credbound.AuditEvent{}, mapError(err))
			return
		}
		defer rows.Close()
		for rows.Next() {
			value, err := scanAuditEvent(rows)
			if err != nil {
				yield(credbound.AuditEvent{}, err)
				return
			}
			if !yield(value, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.AuditEvent{}, err)
		}
	}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAuditEvent(rows rowScanner) (credbound.AuditEvent, error) {
	var value credbound.AuditEvent
	var actor, workspace sql.NullString
	var sequence sql.NullInt64
	if err := rows.Scan(&value.ID, &value.OccurredAt, &value.ActorKind, &actor, &value.Action, &value.ResourceType, &value.ResourceID, &workspace, &value.Outcome, &value.Reason, &value.IPAddress, &value.UserAgent, &sequence, &value.PreviousHash, &value.Hash); err != nil {
		return credbound.AuditEvent{}, err
	}
	value.ActorID, value.WorkspaceID = actor.String, workspace.String
	value.Sequence = sequence.Int64
	return value, nil
}

func insertUser(ctx context.Context, q *db.Queries, user credbound.User) error {
	disabled := int64(0)
	if user.Disabled {
		disabled = 1
	}
	return mapError(q.InsertUser(ctx, db.InsertUserParams{
		ID: user.ID, DisplayName: user.DisplayName, Disabled: disabled, LastSeenAt: nullableTime(user.LastSeenAt),
		CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	}))
}

func insertEmail(ctx context.Context, q *db.Queries, email credbound.EmailAddress, verification credbound.EmailVerificationCredential) error {
	primary := int64(0)
	if email.Primary {
		primary = 1
	}
	return mapError(q.InsertUserEmail(ctx, db.InsertUserEmailParams{
		ID: email.ID, UserID: email.UserID, Address: email.Address, IsPrimary: primary,
		VerifiedAt: nullableTime(email.VerifiedAt), VerificationDigest: verification.Digest,
		VerificationExpiresAt: nullableTime(zeroTimePointer(verification.ExpiresAt)),
		CreatedAt:             email.CreatedAt, UpdatedAt: email.UpdatedAt,
	}))
}

func upsertMembership(ctx context.Context, q *db.Queries, value credbound.Membership) error {
	if value.Status == "" {
		value.Status = credbound.MembershipActive
	}
	if value.ProvisioningSource == "" {
		value.ProvisioningSource = credbound.ProvisioningSourceLocal
	}
	return mapError(q.UpsertMembership(ctx, db.UpsertMembershipParams{
		WorkspaceID: value.WorkspaceID, UserID: value.UserID, Role: string(value.Role), Status: string(value.Status),
		ProvisioningSource: value.ProvisioningSource, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}))
}

func upsertAdmin(ctx context.Context, q *db.Queries, value credbound.InstanceAdministrator) error {
	return mapError(q.UpsertInstanceAdministrator(ctx, db.UpsertInstanceAdministratorParams{
		UserID: value.UserID, Role: string(value.Role), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}))
}

func auditParams(event credbound.AuditEvent) db.InsertAuditParams {
	if event.ActorKind == "" {
		event.ActorKind = credbound.ActorUser
	}
	return db.InsertAuditParams{
		ID: event.ID, OccurredAt: event.OccurredAt, ActorKind: string(event.ActorKind), ActorID: nullableString(event.ActorID), Action: event.Action,
		ResourceType: event.ResourceType, ResourceID: event.ResourceID, WorkspaceID: nullableString(event.WorkspaceID),
		Outcome: string(event.Outcome), Reason: event.Reason,
		IpAddress: event.IPAddress, UserAgent: event.UserAgent,
		Sequence:     sql.NullInt64{Int64: event.Sequence, Valid: event.Sequence > 0},
		PreviousHash: event.PreviousHash, Hash: event.Hash,
	}
}

func userFromEmailRow(row db.GetUserByEmailRow) credbound.User {
	return credbound.User{
		ID: row.ID, Email: row.Email, DisplayName: row.DisplayName, Disabled: row.Disabled == 1,
		LastSeenAt: timePointer(row.LastSeenAt), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func userFromIDRow(row db.GetUserByIDRow) credbound.User {
	return credbound.User{
		ID: row.ID, Email: row.Email, DisplayName: row.DisplayName, Disabled: row.Disabled == 1,
		LastSeenAt: timePointer(row.LastSeenAt), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func workspaceFromRow(row db.CredboundWorkspace) credbound.Workspace {
	return credbound.Workspace{
		ID: row.ID, Name: row.Name, RequireMFA: row.RequireMfa == 1,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		DisabledAt: timePointer(row.DisabledAt),
	}
}

// boolValue converts a policy flag to its SQLite representation.
func boolValue(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

func emailFromRow(row db.CredboundUserEmail) credbound.EmailAddress {
	return credbound.EmailAddress{
		ID: row.ID, UserID: row.UserID, Address: row.Address, Primary: row.IsPrimary == 1,
		VerifiedAt: timePointer(row.VerifiedAt), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func ssoFromRow(row db.CredboundSsoIdentity) credbound.SSOIdentity {
	return credbound.SSOIdentity{
		ID: row.ID, UserID: row.UserID, ProviderConfigurationID: row.ProviderConfigurationID,
		ProviderKind: credbound.SSOProviderKind(row.ProviderKind), Issuer: row.Issuer, Subject: row.Subject,
		Email: row.Email, CreatedAt: row.CreatedAt, LastUsedAt: timePointer(row.LastUsedAt),
	}
}

func patFromRow(row db.CredboundPersonalAccessToken) (credbound.PAT, error) {
	var scopes []string
	if err := json.Unmarshal([]byte(row.ScopesJson), &scopes); err != nil {
		return credbound.PAT{}, err
	}
	return credbound.PAT{
		ID: row.ID, UserID: row.UserID, Name: row.Name, Prefix: row.Prefix, Digest: row.Digest,
		WorkspaceID: row.WorkspaceID.String, Scopes: scopes, CreatedAt: row.CreatedAt,
		ExpiresAt: timePointer(row.ExpiresAt), LastUsedAt: timePointer(row.LastUsedAt), RevokedAt: timePointer(row.RevokedAt),
	}, nil
}

type scanner interface{ Scan(...any) error }

func scanPAT(row scanner) (credbound.PAT, error) {
	var value credbound.PAT
	var workspace sql.NullString
	var scopes string
	var expires, lastUsed, revoked sql.NullTime
	if err := row.Scan(&value.ID, &value.UserID, &value.Name, &value.Prefix, &value.Digest, &workspace, &scopes, &value.CreatedAt, &expires, &lastUsed, &revoked); err != nil {
		return credbound.PAT{}, err
	}
	if err := json.Unmarshal([]byte(scopes), &value.Scopes); err != nil {
		return credbound.PAT{}, err
	}
	value.WorkspaceID = workspace.String
	value.ExpiresAt, value.LastUsedAt, value.RevokedAt = timePointer(expires), timePointer(lastUsed), timePointer(revoked)
	return value, nil
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func zeroTimePointer(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	return &value
}

func timePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	copy := value.Time
	return &copy
}

func affected(count int64, err error) error {
	if err != nil {
		return mapError(err)
	}
	if count == 0 {
		return credbound.ErrNotFound
	}
	return nil
}

func mapError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return credbound.ErrNotFound
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") || strings.Contains(message, "constraint failed") || strings.Contains(message, "duplicate key") {
		return fmt.Errorf("%w: %v", credbound.ErrConflict, err)
	}
	return err
}

type cursor struct {
	Time time.Time `json:"t"`
	ID   string    `json:"id"`
}

func encodeCursor(timestamp time.Time, id string) string {
	payload, _ := json.Marshal(cursor{Time: timestamp, ID: id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(raw string) (cursor, error) {
	if raw == "" {
		return cursor{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return cursor{}, credbound.ErrInvalidInput
	}
	var value cursor
	if err := json.Unmarshal(payload, &value); err != nil || value.Time.IsZero() || value.ID == "" {
		return cursor{}, credbound.ErrInvalidInput
	}
	return value, nil
}

var _ credbound.Store = (*Store)(nil)
var _ credbound.SignupStore = (*Store)(nil)
