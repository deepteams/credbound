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

func (t *Tx) Kind() credbound.StoreKind { return credbound.StoreSQLite }

func (t *Tx) Audit() credbound.AuditEvent { return t.audit }

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

type Option func(*Store)

func WithStreamTimeout(timeout time.Duration) Option {
	return func(store *Store) { store.streamTimeout = timeout }
}

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
		if err := q.InsertWorkspace(ctx, db.InsertWorkspaceParams{ID: workspace.ID, Name: workspace.Name, CreatedAt: workspace.CreatedAt, UpdatedAt: workspace.UpdatedAt, DisabledAt: nullableTime(workspace.DisabledAt)}); err != nil {
			return mapError(err)
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		return upsertAdmin(ctx, q, admin)
	})
}

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

func (s *Store) UserByEmail(ctx context.Context, email string) (credbound.User, error) {
	row, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return credbound.User{}, mapError(err)
	}
	return userFromEmailRow(row), nil
}

func (s *Store) UserByID(ctx context.Context, id string) (credbound.User, error) {
	row, err := s.queries.GetUserByID(ctx, id)
	if err != nil {
		return credbound.User{}, mapError(err)
	}
	return userFromIDRow(row), nil
}

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
			return mapError(q.RevokeUserPATs(ctx, db.RevokeUserPATsParams{UserID: userID, RevokedAt: nullableTime(&at)}))
		}
		return nil
	})
}

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

func (s *Store) PasswordByUserID(ctx context.Context, userID string) (credbound.PasswordCredential, error) {
	row, err := s.queries.GetPassword(ctx, userID)
	if err != nil {
		return credbound.PasswordCredential{}, mapError(err)
	}
	return credbound.PasswordCredential{UserID: row.UserID, Hash: row.Hash, UpdatedAt: row.UpdatedAt}, nil
}

func (s *Store) ReplacePassword(ctx context.Context, password credbound.PasswordCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.ReplacePassword(ctx, db.ReplacePasswordParams{UserID: password.UserID, Hash: password.Hash, UpdatedAt: password.UpdatedAt})
		return affected(count, err)
	})
}

func (s *Store) RecordAuthentication(ctx context.Context, userID string, seenAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchUserLastSeen(ctx, db.TouchUserLastSeenParams{ID: userID, LastSeenAt: nullableTime(&seenAt)})
		return affected(count, err)
	})
}

func (s *Store) SaveEmail(ctx context.Context, email credbound.EmailAddress, verification credbound.EmailVerificationCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error { return insertEmail(ctx, q, email, verification) })
}

func (s *Store) EmailVerificationByID(ctx context.Context, emailID string) (credbound.EmailAddress, credbound.EmailVerificationCredential, error) {
	row, err := s.queries.GetEmailVerification(ctx, emailID)
	if err != nil {
		return credbound.EmailAddress{}, credbound.EmailVerificationCredential{}, mapError(err)
	}
	return emailFromRow(row), credbound.EmailVerificationCredential{
		EmailID: row.ID, Digest: row.VerificationDigest, ExpiresAt: row.VerificationExpiresAt.Time,
	}, nil
}

func (s *Store) VerifyEmail(ctx context.Context, emailID string, verifiedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.VerifyEmail(ctx, db.VerifyEmailParams{ID: emailID, VerifiedAt: nullableTime(&verifiedAt)})
		return affected(count, err)
	})
}

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
		}
		return used, nil
	})
	return used, err
}

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
		}
		return used, nil
	})
	return used, err
}

func (s *Store) DisableTOTP(ctx context.Context, userID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteTOTP(ctx, userID)
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.DeleteRecoveryCodes(ctx, userID))
	})
}

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

func (s *Store) SavePasskey(ctx context.Context, passkey credbound.Passkey, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		return mapError(q.InsertPasskey(ctx, db.InsertPasskeyParams{
			ID: passkey.ID, UserID: passkey.UserID, Name: passkey.Name,
			CredentialID: passkey.CredentialID, CredentialJson: passkey.CredentialJSON, CreatedAt: passkey.CreatedAt,
		}))
	})
}

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

func (s *Store) DeletePasskey(ctx context.Context, userID, passkeyID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeletePasskey(ctx, db.DeletePasskeyParams{UserID: userID, ID: passkeyID})
		return affected(count, err)
	})
}

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

func (s *Store) PATByPrefix(ctx context.Context, prefix string) (credbound.PAT, error) {
	row, err := s.queries.GetPATByPrefix(ctx, prefix)
	if err != nil {
		return credbound.PAT{}, mapError(err)
	}
	return patFromRow(row)
}

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

func (s *Store) RevokePAT(ctx context.Context, userID, id string, revokedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.RevokePAT(ctx, db.RevokePATParams{UserID: userID, ID: id, RevokedAt: nullableTime(&revokedAt)})
		return affected(count, err)
	})
}

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

func (s *Store) CreateWorkspace(ctx context.Context, workspace credbound.Workspace, owner credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := q.InsertWorkspace(ctx, db.InsertWorkspaceParams{
			ID: workspace.ID, Name: workspace.Name, CreatedAt: workspace.CreatedAt,
			UpdatedAt: workspace.UpdatedAt, DisabledAt: nullableTime(workspace.DisabledAt),
		}); err != nil {
			return mapError(err)
		}
		return upsertMembership(ctx, q, owner)
	})
}

func (s *Store) WorkspaceByID(ctx context.Context, workspaceID string) (credbound.Workspace, error) {
	row, err := s.queries.GetWorkspace(ctx, workspaceID)
	if err != nil {
		return credbound.Workspace{}, mapError(err)
	}
	return workspaceFromRow(row), nil
}

func (s *Store) UpdateWorkspace(ctx context.Context, workspace credbound.Workspace, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.UpdateWorkspace(ctx, db.UpdateWorkspaceParams{ID: workspace.ID, Name: workspace.Name, UpdatedAt: workspace.UpdatedAt})
		return affected(count, err)
	})
}

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

func (s *Store) Workspaces(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return s.workspaces(ctx, "", page)
}

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
		query := `SELECT w.id, w.name, w.created_at, w.updated_at, w.disabled_at
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
			if err := rows.Scan(&value.ID, &value.Name, &value.CreatedAt, &value.UpdatedAt, &disabled); err != nil {
				yield(credbound.PageEvent[credbound.Workspace]{}, err)
				return
			}
			value.DisabledAt = timePointer(disabled)
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

func (s *Store) InstanceAdministrator(ctx context.Context, userID string) (credbound.InstanceAdministrator, error) {
	row, err := s.queries.GetInstanceAdministrator(ctx, userID)
	if err != nil {
		return credbound.InstanceAdministrator{}, mapError(err)
	}
	return credbound.InstanceAdministrator{UserID: row.UserID, Role: credbound.InstanceRole(row.Role), CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}, nil
}

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

func (s *Store) SSOIdentity(ctx context.Context, providerConfigurationID, issuer, subject string) (credbound.SSOIdentity, error) {
	row, err := s.queries.GetSSOIdentity(ctx, db.GetSSOIdentityParams{
		ProviderConfigurationID: providerConfigurationID, Issuer: issuer, Subject: subject,
	})
	if err != nil {
		return credbound.SSOIdentity{}, mapError(err)
	}
	return ssoFromRow(row), nil
}

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

func (s *Store) UnlinkSSO(ctx context.Context, userID, identityID string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteSSOIdentity(ctx, db.DeleteSSOIdentityParams{UserID: userID, ID: identityID})
		return affected(count, err)
	})
}

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

func (s *Store) AppendAudit(ctx context.Context, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(*db.Queries) error { return nil })
}

func (s *Store) AuditEvents(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return s.auditEvents(ctx, page, `workspace_id = ? AND`, []any{workspaceID})
}

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
		query := `SELECT id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason
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
			var value credbound.AuditEvent
			var actor, workspace sql.NullString
			if err := rows.Scan(&value.ID, &value.OccurredAt, &value.ActorKind, &actor, &value.Action, &value.ResourceType, &value.ResourceID, &workspace, &value.Outcome, &value.Reason); err != nil {
				yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
				return
			}
			value.ActorID, value.WorkspaceID = actor.String, workspace.String
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
	if err := q.InsertAudit(ctx, auditParams(commit.Audit)); err != nil {
		return fmt.Errorf("%w: %v", credbound.ErrAuditUnavailable, err)
	}
	return mapError(tx.Commit())
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
		ID: row.ID, Name: row.Name, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
		DisabledAt: timePointer(row.DisabledAt),
	}
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
