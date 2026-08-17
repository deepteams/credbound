package sqlite

import (
	"context"
	"database/sql"
	"iter"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
)

func (s *Store) CreateWorkspaceDomain(ctx context.Context, domain credbound.WorkspaceDomain, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspace(ctx, domain.WorkspaceID); err != nil {
			return mapError(err)
		}
		return mapError(q.InsertWorkspaceDomain(ctx, db.InsertWorkspaceDomainParams{
			ID: domain.ID, WorkspaceID: domain.WorkspaceID, Domain: domain.Domain, Challenge: domain.Challenge,
			ConfirmedAt: nullableTime(domain.ConfirmedAt), AutoJoin: boolValue(domain.AutoJoin),
			AutoJoinRole: string(domain.AutoJoinRole), SsoProviderConfigurationID: domain.SSOProviderConfigurationID,
			EnforceSso: boolValue(domain.EnforceSSO), CreatedAt: domain.CreatedAt, UpdatedAt: domain.UpdatedAt,
		}))
	})
}

func (s *Store) WorkspaceDomainByID(ctx context.Context, id string) (credbound.WorkspaceDomain, error) {
	row, err := s.queries.GetWorkspaceDomain(ctx, id)
	if err != nil {
		return credbound.WorkspaceDomain{}, mapError(err)
	}
	return workspaceDomainFromRow(row), nil
}

func (s *Store) ConfirmedWorkspaceDomainByName(ctx context.Context, name string) (credbound.WorkspaceDomain, error) {
	row, err := s.queries.GetConfirmedWorkspaceDomainByName(ctx, name)
	if err != nil {
		return credbound.WorkspaceDomain{}, mapError(err)
	}
	return workspaceDomainFromRow(row), nil
}

func (s *Store) ConfirmWorkspaceDomain(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspaceDomain(ctx, id); err != nil {
			return mapError(err)
		}
		count, err := q.ConfirmWorkspaceDomain(ctx, db.ConfirmWorkspaceDomainParams{ID: id, ConfirmedAt: nullableTime(&at)})
		if err != nil {
			return mapError(err)
		}
		// The domain exists, so zero affected rows means it was already
		// confirmed by a concurrent call.
		if count == 0 {
			return credbound.ErrConflict
		}
		return nil
	})
}

func (s *Store) UpdateWorkspaceDomainPolicy(ctx context.Context, id string, policy credbound.WorkspaceDomainPolicyInput, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspaceDomain(ctx, id); err != nil {
			return mapError(err)
		}
		count, err := q.UpdateWorkspaceDomainPolicy(ctx, db.UpdateWorkspaceDomainPolicyParams{
			ID: id, AutoJoin: boolValue(policy.AutoJoin), AutoJoinRole: string(policy.AutoJoinRole),
			SsoProviderConfigurationID: policy.SSOProviderConfigurationID, EnforceSso: boolValue(policy.EnforceSSO),
			UpdatedAt: at,
		})
		if err != nil {
			return mapError(err)
		}
		// The domain exists, so zero affected rows means it is not confirmed
		// and must not carry policy.
		if count == 0 {
			return credbound.ErrConflict
		}
		return nil
	})
}

func (s *Store) DeleteWorkspaceDomain(ctx context.Context, id string, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteWorkspaceDomain(ctx, id)
		return affected(count, err)
	})
}

func (s *Store) WorkspaceDomains(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.WorkspaceDomain], error] {
	return func(yield func(credbound.PageEvent[credbound.WorkspaceDomain], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, `SELECT id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at
FROM credbound_workspace_domains
WHERE workspace_id = ? AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?))
ORDER BY created_at DESC, id DESC LIMIT ?`, workspaceID, cursor.ID, cursor.Time, cursor.Time, cursor.ID, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.WorkspaceDomain
		count := 0
		for rows.Next() {
			value, err := scanWorkspaceDomain(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.WorkspaceDomain](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last = value
			count++
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.WorkspaceDomain](credbound.PageEnd{}), nil)
	}
}

func (s *Store) JITProvisionSSOUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, membership credbound.Membership, identity credbound.SSOIdentity, _ time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, credbound.EmailVerificationCredential{}); err != nil {
			return err
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		return mapError(q.InsertSSOIdentity(ctx, db.InsertSSOIdentityParams{
			ID: identity.ID, UserID: identity.UserID, ProviderConfigurationID: identity.ProviderConfigurationID,
			ProviderKind: string(identity.ProviderKind), Issuer: identity.Issuer, Subject: identity.Subject,
			Email: identity.Email, CreatedAt: identity.CreatedAt, LastUsedAt: nullableTime(identity.LastUsedAt),
		}))
	})
}

func workspaceDomainFromRow(row db.CredboundWorkspaceDomain) credbound.WorkspaceDomain {
	return credbound.WorkspaceDomain{
		ID: row.ID, WorkspaceID: row.WorkspaceID, Domain: row.Domain, Challenge: row.Challenge,
		ConfirmedAt: timePointer(row.ConfirmedAt), AutoJoin: row.AutoJoin == 1,
		AutoJoinRole: credbound.Role(row.AutoJoinRole), SSOProviderConfigurationID: row.SsoProviderConfigurationID,
		EnforceSSO: row.EnforceSso == 1, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func scanWorkspaceDomain(row scanner) (credbound.WorkspaceDomain, error) {
	var value credbound.WorkspaceDomain
	var role string
	var autoJoin, enforceSSO int64
	var confirmed sql.NullTime
	if err := row.Scan(&value.ID, &value.WorkspaceID, &value.Domain, &value.Challenge, &confirmed, &autoJoin, &role, &value.SSOProviderConfigurationID, &enforceSSO, &value.CreatedAt, &value.UpdatedAt); err != nil {
		return credbound.WorkspaceDomain{}, err
	}
	value.ConfirmedAt = timePointer(confirmed)
	value.AutoJoinRole = credbound.Role(role)
	value.AutoJoin, value.EnforceSSO = autoJoin == 1, enforceSSO == 1
	return value, nil
}

var _ credbound.DomainStore = (*Store)(nil)
