package postgresql

import (
	"context"
	"database/sql"
	"iter"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/internal/dbtype"
	db "github.com/deepteams/credbound/internal/sqlc/postgresql"
)

// CreateWorkspaceDomain stores an unconfirmed domain claim; a domain already
// claimed by any workspace reports credbound.ErrConflict, except that a stale
// pending claim — still unconfirmed and created before staleBefore — lost its
// reservation and is replaced in the same transaction.
func (s *Store) CreateWorkspaceDomain(ctx context.Context, domain credbound.WorkspaceDomain, staleBefore time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspace(ctx, dbID(domain.WorkspaceID)); err != nil {
			return mapError(err)
		}
		if _, err := q.DeleteStaleWorkspaceDomainClaim(ctx, db.DeleteStaleWorkspaceDomainClaimParams{Domain: domain.Domain, StaleBefore: staleBefore}); err != nil {
			return mapError(err)
		}
		return mapError(q.InsertWorkspaceDomain(ctx, db.InsertWorkspaceDomainParams{
			ID: dbID(domain.ID), WorkspaceID: dbID(domain.WorkspaceID), Domain: domain.Domain, Challenge: domain.Challenge,
			ConfirmedAt: nullableTime(domain.ConfirmedAt), AutoJoin: domain.AutoJoin,
			AutoJoinRole: string(domain.AutoJoinRole), SsoProviderConfigurationID: dbID(domain.SSOProviderConfigurationID),
			EnforceSso: domain.EnforceSSO, CreatedAt: domain.CreatedAt, UpdatedAt: domain.UpdatedAt,
		}))
	})
}

// WorkspaceDomainByID returns the domain record with the given ID.
func (s *Store) WorkspaceDomainByID(ctx context.Context, id credbound.UUID) (credbound.WorkspaceDomain, error) {
	row, err := s.queries.GetWorkspaceDomain(ctx, dbID(id))
	if err != nil {
		return credbound.WorkspaceDomain{}, mapError(err)
	}
	return workspaceDomainFromRow(row), nil
}

// ConfirmedWorkspaceDomainByName resolves a confirmed domain by name;
// unknown or unconfirmed domains report credbound.ErrNotFound.
func (s *Store) ConfirmedWorkspaceDomainByName(ctx context.Context, name string) (credbound.WorkspaceDomain, error) {
	row, err := s.queries.GetConfirmedWorkspaceDomainByName(ctx, name)
	if err != nil {
		return credbound.WorkspaceDomain{}, mapError(err)
	}
	return workspaceDomainFromRow(row), nil
}

// ConfirmWorkspaceDomain marks the domain verified; confirming twice reports
// credbound.ErrConflict.
func (s *Store) ConfirmWorkspaceDomain(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspaceDomain(ctx, dbID(id)); err != nil {
			return mapError(err)
		}
		count, err := q.ConfirmWorkspaceDomain(ctx, db.ConfirmWorkspaceDomainParams{ID: dbID(id), ConfirmedAt: nullableTime(&at)})
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

// UpdateWorkspaceDomainPolicy replaces the auto-join and SSO-enforcement
// policy of a confirmed domain; an unconfirmed domain reports
// credbound.ErrConflict.
func (s *Store) UpdateWorkspaceDomainPolicy(ctx context.Context, id credbound.UUID, policy credbound.WorkspaceDomainPolicyInput, at time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if _, err := q.GetWorkspaceDomain(ctx, dbID(id)); err != nil {
			return mapError(err)
		}
		count, err := q.UpdateWorkspaceDomainPolicy(ctx, db.UpdateWorkspaceDomainPolicyParams{
			ID: dbID(id), AutoJoin: policy.AutoJoin, AutoJoinRole: string(policy.AutoJoinRole),
			SsoProviderConfigurationID: dbID(policy.SSOProviderConfigurationID), EnforceSso: policy.EnforceSSO,
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

// DeleteWorkspaceDomain removes the domain claim.
func (s *Store) DeleteWorkspaceDomain(ctx context.Context, id credbound.UUID, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteWorkspaceDomain(ctx, dbID(id))
		return affected(count, err)
	})
}

// WorkspaceDomains streams the workspace's domains, newest first, as one
// cursor page.
func (s *Store) WorkspaceDomains(ctx context.Context, workspaceID credbound.UUID, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.WorkspaceDomain], error] {
	return func(yield func(credbound.PageEvent[credbound.WorkspaceDomain], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
			return
		}
		query, args := workspaceDomainsFirstPage, []any{workspaceID, page.Limit + 1}
		if cursor.ID != (credbound.UUID{}) {
			query, args = workspaceDomainsAfterCursor, []any{workspaceID, cursor.Time, cursor.ID, page.Limit + 1}
		}
		rows, err := s.query(streamCtx, query, args...)
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

// JITProvisionSSOUser atomically creates a user with a verified email,
// workspace membership and linked SSO identity for domain-based just-in-time
// provisioning.
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
			ID: dbID(identity.ID), UserID: dbID(identity.UserID), ProviderConfigurationID: dbID(identity.ProviderConfigurationID),
			ProviderKind: string(identity.ProviderKind), Issuer: identity.Issuer, Subject: identity.Subject,
			Email: identity.Email, CreatedAt: identity.CreatedAt, LastUsedAt: nullableTime(identity.LastUsedAt),
		}))
	})
}

func workspaceDomainFromRow(row db.CredboundWorkspaceDomain) credbound.WorkspaceDomain {
	return credbound.WorkspaceDomain{
		ID: domainID(row.ID), WorkspaceID: domainID(row.WorkspaceID), Domain: row.Domain, Challenge: row.Challenge,
		ConfirmedAt: timePointer(row.ConfirmedAt), AutoJoin: row.AutoJoin,
		AutoJoinRole: credbound.Role(row.AutoJoinRole), SSOProviderConfigurationID: domainID(row.SsoProviderConfigurationID),
		EnforceSSO: row.EnforceSso, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
}

func scanWorkspaceDomain(row scanner) (credbound.WorkspaceDomain, error) {
	var value credbound.WorkspaceDomain
	var role string
	var autoJoin, enforceSSO bool
	var confirmed sql.NullTime
	// The SSO provider reference is nullable, so it scans through dbtype: pgx
	// will not put NULL into sixteen bytes.
	var provider dbtype.UUID
	if err := row.Scan(&value.ID, &value.WorkspaceID, &value.Domain, &value.Challenge, &confirmed, &autoJoin, &role, &provider, &enforceSSO, &value.CreatedAt, &value.UpdatedAt); err != nil {
		return credbound.WorkspaceDomain{}, err
	}
	value.SSOProviderConfigurationID = domainID(provider)
	value.ConfirmedAt = timePointer(confirmed)
	value.AutoJoinRole = credbound.Role(role)
	value.AutoJoin, value.EnforceSSO = autoJoin, enforceSSO
	return value, nil
}

var _ credbound.DomainStore = (*Store)(nil)
