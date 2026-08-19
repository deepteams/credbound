package postgresql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/postgresql"
)

// CreateOAuthIssuer stores an authorization server issuer; a duplicate ID or
// URL reports credbound.ErrConflict.
func (s *Store) CreateOAuthIssuer(ctx context.Context, value credbound.OAuthIssuer, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertIssuer(ctx, db.OAuthInsertIssuerParams{ID: dbID(value.ID), Issuer: value.Issuer, CreatedAt: value.CreatedAt, DataJson: data}))
	})
}

// SetOAuthIssuerDisabled enables or disables the issuer.
func (s *Store) SetOAuthIssuerDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthIssuer](q.OAuthIssuerJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.DisabledAt = nil
		if disabled {
			value.DisabledAt = &at
		}
		value.UpdatedAt = at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		if err := affected(q.OAuthUpdateIssuerJSON(ctx, db.OAuthUpdateIssuerJSONParams{ID: dbID(id), DataJson: data})); err != nil {
			return err
		}
		if disabled {
			return s.revokeOAuthGrantsByIssuer(ctx, q, at, id)
		}
		return nil
	})
}

// UpdateOAuthIssuer persists the issuer's mutable attributes.
func (s *Store) UpdateOAuthIssuer(ctx context.Context, value credbound.OAuthIssuer, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return affected(q.OAuthUpdateIssuer(ctx, db.OAuthUpdateIssuerParams{ID: dbID(value.ID), Issuer: value.Issuer, DataJson: data}))
	})
}

// OAuthIssuerByID returns the issuer with the given ID.
func (s *Store) OAuthIssuerByID(ctx context.Context, id credbound.UUID) (credbound.OAuthIssuer, error) {
	return oauthDecodeQuery[credbound.OAuthIssuer](s.queries.OAuthIssuerJSONByID(ctx, dbID(id)))
}

// OAuthIssuerByURL resolves an issuer by its canonical URL.
func (s *Store) OAuthIssuerByURL(ctx context.Context, issuer string) (credbound.OAuthIssuer, error) {
	return oauthDecodeQuery[credbound.OAuthIssuer](s.queries.OAuthIssuerJSONByURL(ctx, issuer))
}

// OAuthIssuers streams all issuers, newest first, as one cursor page.
func (s *Store) OAuthIssuers(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthIssuer], error] {
	return oauthPage(s, ctx, "credbound.oauth_issuers", nil, page, func(value credbound.OAuthIssuer) credbound.OAuthIssuer { return value })
}

// CreateOAuthProtectedResource stores a protected resource; a duplicate ID
// or URI reports credbound.ErrConflict.
func (s *Store) CreateOAuthProtectedResource(ctx context.Context, value credbound.OAuthProtectedResource, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertResource(ctx, db.OAuthInsertResourceParams{ID: dbID(value.ID), IssuerID: dbID(value.IssuerID), WorkspaceID: dbID(value.WorkspaceID), Resource: value.Resource, CreatedAt: value.CreatedAt, DataJson: data}))
	})
}

// SetOAuthProtectedResourceDisabled enables or disables the resource.
func (s *Store) SetOAuthProtectedResourceDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthProtectedResource](q.OAuthResourceJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.DisabledAt = nil
		if disabled {
			value.DisabledAt = &at
		}
		value.UpdatedAt = at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		if err := affected(q.OAuthUpdateResourceJSON(ctx, db.OAuthUpdateResourceJSONParams{ID: dbID(id), DataJson: data})); err != nil {
			return err
		}
		if disabled {
			return s.revokeOAuthGrantsByResource(ctx, q, at, id)
		}
		return nil
	})
}

// OAuthProtectedResourceByID returns the resource with the given ID.
func (s *Store) OAuthProtectedResourceByID(ctx context.Context, id credbound.UUID) (credbound.OAuthProtectedResource, error) {
	return oauthDecodeQuery[credbound.OAuthProtectedResource](s.queries.OAuthResourceJSONByID(ctx, dbID(id)))
}

// OAuthProtectedResourceByURI resolves a resource by its canonical URI.
func (s *Store) OAuthProtectedResourceByURI(ctx context.Context, resource string) (credbound.OAuthProtectedResource, error) {
	return oauthDecodeQuery[credbound.OAuthProtectedResource](s.queries.OAuthResourceJSONByURI(ctx, resource))
}

// OAuthProtectedResources streams resources, optionally filtered by
// workspace, newest first, as one cursor page.
func (s *Store) OAuthProtectedResources(ctx context.Context, workspaceID credbound.UUID, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthProtectedResource], error] {
	return oauthPage(s, ctx, "credbound.oauth_resources", []oauthFilter{{"workspace_id", workspaceID.String()}}, page, func(value credbound.OAuthProtectedResource) credbound.OAuthProtectedResource { return value })
}

// CreateOAuthClient stores a dynamically registered client, consuming a use
// of the initial access token in the same commit when one gated the
// registration.
func (s *Store) CreateOAuthClient(ctx context.Context, value credbound.OAuthClient, initialID credbound.UUID, usedAt time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		issuer, err := oauthDecodeQuery[credbound.OAuthIssuer](q.OAuthIssuerJSONByID(ctx, dbID(value.IssuerID)))
		if err != nil {
			return err
		}
		if value.Source == credbound.OAuthClientDCR && issuer.DCRMode == credbound.OAuthDCROpen {
			// Open registration counts existing clients then inserts, with no
			// indexed guard, so the issuer row is locked first: without it two
			// concurrent registrations could each read a stale count and
			// overrun the limit.
			if _, err := q.OAuthLockIssuer(ctx, dbID(value.IssuerID)); err != nil {
				return mapError(err)
			}
			records, err := q.OAuthClientJSONsByIssuer(ctx, dbID(value.IssuerID))
			if err != nil {
				return mapError(err)
			}
			active := 0
			for _, raw := range records {
				existing, err := oauthDecode[credbound.OAuthClient](raw)
				if err != nil {
					return err
				}
				if existing.Source == credbound.OAuthClientDCR && existing.DisabledAt == nil {
					active++
				}
			}
			if active >= issuer.DCROpenRegistrationLimit {
				return credbound.ErrConflict
			}
		}
		if initialID != (credbound.UUID{}) {
			token, err := oauthDecodeQuery[credbound.OAuthInitialAccessToken](q.OAuthInitialAccessTokenJSONByIDAndIssuer(ctx, db.OAuthInitialAccessTokenJSONByIDAndIssuerParams{ID: dbID(initialID), IssuerID: dbID(value.IssuerID)}))
			if err != nil {
				return err
			}
			if token.RevokedAt != nil || !usedAt.Before(token.ExpiresAt) || token.RegistrationCount >= token.MaxRegistrations {
				return credbound.ErrConflict
			}
			previousCount := token.RegistrationCount
			token.RegistrationCount++
			tokenData, err := oauthJSON(token)
			if err != nil {
				return err
			}
			count, err := q.OAuthUseInitialAccessToken(ctx, db.OAuthUseInitialAccessTokenParams{
				ID: dbID(token.ID), RegistrationCount: int32(token.RegistrationCount), DataJson: tokenData, RegistrationCount_2: int32(previousCount), ExpiresAt: usedAt,
			})
			if err != nil || count != 1 {
				return credbound.ErrConflict
			}
		}
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertClient(ctx, db.OAuthInsertClientParams{ID: dbID(value.ID), IssuerID: dbID(value.IssuerID), ClientID: value.ClientID, CreatedAt: value.CreatedAt, DataJson: data}))
	})
}

// UpsertOAuthCIMDClient inserts or refreshes a client registered through a
// Client Identifier Metadata Document.
func (s *Store) UpsertOAuthCIMDClient(ctx context.Context, value credbound.OAuthClient, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthUpsertCIMDClient(ctx, db.OAuthUpsertCIMDClientParams{ID: dbID(value.ID), IssuerID: dbID(value.IssuerID), ClientID: value.ClientID, CreatedAt: value.CreatedAt, DataJson: data}))
	})
}

// SetOAuthClientDisabled enables or disables the client.
func (s *Store) SetOAuthClientDisabled(ctx context.Context, id credbound.UUID, disabled bool, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthClient](q.OAuthClientJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.DisabledAt = nil
		if disabled {
			value.DisabledAt = &at
		}
		value.UpdatedAt = at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		if err := affected(q.OAuthUpdateClientJSON(ctx, db.OAuthUpdateClientJSONParams{ID: dbID(id), DataJson: data})); err != nil {
			return err
		}
		if disabled {
			return s.revokeOAuthGrantsByClient(ctx, q, at, id)
		}
		return nil
	})
}

// RotateOAuthClientCredentials replaces the client's secret digest and/or
// inline JWKS (with its recomputed metadata hash) after an administrative
// credential rotation.
func (s *Store) RotateOAuthClientCredentials(ctx context.Context, id credbound.UUID, secretDigest, jwks, metadataHash []byte, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthClient](q.OAuthClientJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		if secretDigest != nil {
			value.SecretDigest = secretDigest
		}
		if jwks != nil {
			value.JWKS = jwks
			value.MetadataHash = metadataHash
		}
		value.UpdatedAt = at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return affected(q.OAuthUpdateClientJSON(ctx, db.OAuthUpdateClientJSONParams{ID: dbID(id), DataJson: data}))
	})
}

// OAuthClientByID returns the client with the given record ID.
func (s *Store) OAuthClientByID(ctx context.Context, id credbound.UUID) (credbound.OAuthClient, error) {
	return oauthDecodeQuery[credbound.OAuthClient](s.queries.OAuthClientJSONByID(ctx, dbID(id)))
}

// OAuthClientByClientID resolves the issuer's client by its OAuth client_id.
func (s *Store) OAuthClientByClientID(ctx context.Context, issuerID credbound.UUID, clientID string) (credbound.OAuthClient, error) {
	return oauthDecodeQuery[credbound.OAuthClient](s.queries.OAuthClientJSONByClientID(ctx, db.OAuthClientJSONByClientIDParams{IssuerID: dbID(issuerID), ClientID: clientID}))
}

// OAuthClients streams the issuer's clients, newest first, as one cursor
// page.
func (s *Store) OAuthClients(ctx context.Context, issuerID credbound.UUID, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthClient], error] {
	return oauthPage(s, ctx, "credbound.oauth_clients", []oauthFilter{{"issuer_id", issuerID.String()}}, page, func(value credbound.OAuthClient) credbound.OAuthClient {
		value.SecretDigest = nil
		return value
	})
}

// CreateOAuthInitialAccessToken stores an initial access token for gated
// dynamic client registration.
func (s *Store) CreateOAuthInitialAccessToken(ctx context.Context, value credbound.OAuthInitialAccessToken, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertInitialAccessToken(ctx, db.OAuthInsertInitialAccessTokenParams{
			ID: dbID(value.ID), IssuerID: dbID(value.IssuerID), Prefix: value.Prefix, RegistrationCount: int32(value.RegistrationCount), MaxRegistrations: int32(value.MaxRegistrations), ExpiresAt: value.ExpiresAt, RevokedAt: nullableTime(value.RevokedAt), DataJson: data,
		}))
	})
}

// OAuthInitialAccessTokenByPrefix returns the token record addressed by its
// lookup prefix.
func (s *Store) OAuthInitialAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthInitialAccessToken, error) {
	return oauthDecodeQuery[credbound.OAuthInitialAccessToken](s.queries.OAuthInitialAccessTokenJSONByPrefix(ctx, prefix))
}

// OAuthInitialAccessTokens streams the issuer's DCR bootstrap credentials,
// oldest first, revoked ones included and digests omitted.
func (s *Store) OAuthInitialAccessTokens(ctx context.Context, issuerID credbound.UUID) iter.Seq2[credbound.OAuthInitialAccessToken, error] {
	return func(yield func(credbound.OAuthInitialAccessToken, error) bool) {
		records, err := s.queries.OAuthInitialAccessTokenJSONsByIssuer(ctx, dbID(issuerID))
		if err != nil {
			yield(credbound.OAuthInitialAccessToken{}, mapError(err))
			return
		}
		for _, raw := range records {
			value, err := oauthDecode[credbound.OAuthInitialAccessToken](raw)
			if err != nil {
				yield(credbound.OAuthInitialAccessToken{}, err)
				return
			}
			value.Digest = nil
			if !yield(value, nil) {
				return
			}
		}
	}
}

// RevokeOAuthInitialAccessToken marks the token revoked.
func (s *Store) RevokeOAuthInitialAccessToken(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthInitialAccessToken](q.OAuthInitialAccessTokenJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.RevokedAt = &at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return affected(q.OAuthRevokeInitialAccessToken(ctx, db.OAuthRevokeInitialAccessTokenParams{ID: dbID(id), RevokedAt: nullableTime(&at), DataJson: data}))
	})
}

// CreateOAuthGrantAndCode atomically stores a user grant with its single-use
// authorization code.
func (s *Store) CreateOAuthGrantAndCode(ctx context.Context, grant credbound.OAuthGrant, code credbound.OAuthAuthorizationCode, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		grantData, err := oauthJSON(grant)
		if err != nil {
			return err
		}
		if err := q.OAuthInsertGrant(ctx, db.OAuthInsertGrantParams{ID: dbID(grant.ID), ClientRecordID: dbID(grant.ClientRecordID), ResourceID: dbID(grant.ResourceID), UserID: dbID(grant.UserID), WorkspaceID: dbID(grant.WorkspaceID), CreatedAt: grant.CreatedAt, DataJson: grantData}); err != nil {
			return mapError(err)
		}
		codeData, err := oauthJSON(code)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertAuthorizationCode(ctx, db.OAuthInsertAuthorizationCodeParams{ID: dbID(code.ID), Prefix: code.Prefix, GrantID: dbID(code.GrantID), UsedAt: nullableTime(code.UsedAt), ExpiresAt: code.ExpiresAt, DataJson: codeData}))
	})
}

// OAuthGrant returns the grant with the given ID.
func (s *Store) OAuthGrant(ctx context.Context, id credbound.UUID) (credbound.OAuthGrant, error) {
	return oauthDecodeQuery[credbound.OAuthGrant](s.queries.OAuthGrantJSONByID(ctx, dbID(id)))
}

// RevokeOAuthGrant revokes the grant together with its outstanding access
// and refresh tokens.
func (s *Store) RevokeOAuthGrant(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error { return s.revokeOAuthGrant(ctx, q, id, at) })
}

// OAuthGrants streams grants, optionally filtered by user and workspace,
// newest first, as one cursor page.
func (s *Store) OAuthGrants(ctx context.Context, userID, workspaceID credbound.UUID, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthGrant], error] {
	return oauthPage(s, ctx, "credbound.oauth_grants", []oauthFilter{{"user_id", userID.String()}, {"workspace_id", workspaceID.String()}}, page, func(value credbound.OAuthGrant) credbound.OAuthGrant { return value })
}

// OAuthAuthorizationCodeByPrefix returns the authorization code record
// addressed by its lookup prefix.
func (s *Store) OAuthAuthorizationCodeByPrefix(ctx context.Context, prefix string) (credbound.OAuthAuthorizationCode, error) {
	return oauthDecodeQuery[credbound.OAuthAuthorizationCode](s.queries.OAuthAuthorizationCodeJSONByPrefix(ctx, prefix))
}

// ConsumeOAuthAuthorizationCode atomically marks the single-use code
// consumed and stores the access and optional refresh token it was exchanged
// for.
func (s *Store) ConsumeOAuthAuthorizationCode(ctx context.Context, codeID credbound.UUID, usedAt time.Time, access credbound.OAuthAccessToken, refresh *credbound.OAuthRefreshToken, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		code, err := oauthDecodeQuery[credbound.OAuthAuthorizationCode](q.OAuthAuthorizationCodeJSONByID(ctx, dbID(codeID)))
		if err != nil {
			return err
		}
		code.UsedAt = &usedAt
		data, err := oauthJSON(code)
		if err != nil {
			return err
		}
		count, err := q.OAuthConsumeAuthorizationCode(ctx, db.OAuthConsumeAuthorizationCodeParams{ID: dbID(codeID), UsedAt: nullableTime(&usedAt), DataJson: data, ExpiresAt: usedAt})
		if err != nil || count != 1 {
			return credbound.ErrConflict
		}
		if err := insertOAuthAccessToken(ctx, q, access); err != nil {
			return err
		}
		if refresh != nil {
			return insertOAuthRefreshToken(ctx, q, *refresh)
		}
		return nil
	})
}

// OAuthAccessTokenByPrefix returns the access token record addressed by its
// lookup prefix.
func (s *Store) OAuthAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthAccessToken, error) {
	return oauthDecodeQuery[credbound.OAuthAccessToken](s.queries.OAuthAccessTokenJSONByPrefix(ctx, prefix))
}

// CreateOAuthClientAccessToken stores a client-credentials access token.
func (s *Store) CreateOAuthClientAccessToken(ctx context.Context, value credbound.OAuthClientAccessToken, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return mapError(q.OAuthInsertClientAccessToken(ctx, db.OAuthInsertClientAccessTokenParams{ID: dbID(value.ID), Prefix: value.Prefix, ClientRecordID: dbID(value.ClientRecordID), DataJson: data}))
	})
}

// OAuthClientAccessTokenByPrefix returns the client-credentials access token
// addressed by its lookup prefix.
func (s *Store) OAuthClientAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthClientAccessToken, error) {
	return oauthDecodeQuery[credbound.OAuthClientAccessToken](s.queries.OAuthClientAccessTokenJSONByPrefix(ctx, prefix))
}

// RevokeOAuthClientAccessToken marks the client-credentials access token
// revoked.
func (s *Store) RevokeOAuthClientAccessToken(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthClientAccessToken](q.OAuthClientAccessTokenJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.RevokedAt = &at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return affected(q.OAuthUpdateClientAccessTokenJSON(ctx, db.OAuthUpdateClientAccessTokenJSONParams{ID: dbID(id), DataJson: data}))
	})
}

// OAuthRefreshTokenByPrefix returns the refresh token record addressed by
// its lookup prefix.
func (s *Store) OAuthRefreshTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthRefreshToken, error) {
	row, err := s.queries.OAuthRefreshTokenByPrefix(ctx, prefix)
	if err != nil {
		return credbound.OAuthRefreshToken{}, mapError(err)
	}
	value, err := oauthDecode[credbound.OAuthRefreshToken](row.DataJson)
	if err != nil {
		return credbound.OAuthRefreshToken{}, err
	}
	if row.UsedAt.Valid {
		value.UsedAt = &row.UsedAt.Time
	}
	if row.RevokedAt.Valid {
		value.RevokedAt = &row.RevokedAt.Time
	}
	return value, nil
}

// RotateOAuthRefreshToken atomically retires the used refresh token and
// stores its successor pair, keeping the family linked for reuse detection.
func (s *Store) RotateOAuthRefreshToken(ctx context.Context, previousID credbound.UUID, usedAt time.Time, access credbound.OAuthAccessToken, refresh credbound.OAuthRefreshToken, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		previous, err := oauthDecodeQuery[credbound.OAuthRefreshToken](q.OAuthRefreshTokenJSONByID(ctx, dbID(previousID)))
		if err != nil {
			return err
		}
		if previous.FamilyID != refresh.FamilyID || previous.GrantID != refresh.GrantID {
			return credbound.ErrConflict
		}
		previous.UsedAt, previous.ReplacedByID = &usedAt, refresh.ID
		data, err := oauthJSON(previous)
		if err != nil {
			return err
		}
		count, err := q.OAuthConsumeRefreshToken(ctx, db.OAuthConsumeRefreshTokenParams{ID: dbID(previousID), UsedAt: nullableTime(&usedAt), DataJson: data, ExpiresAt: usedAt})
		if err != nil || count != 1 {
			return credbound.ErrConflict
		}
		if err := insertOAuthAccessToken(ctx, q, access); err != nil {
			return err
		}
		return insertOAuthRefreshToken(ctx, q, refresh)
	})
}

// RevokeOAuthAccessToken marks the access token revoked.
func (s *Store) RevokeOAuthAccessToken(ctx context.Context, id credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		value, err := oauthDecodeQuery[credbound.OAuthAccessToken](q.OAuthAccessTokenJSONByID(ctx, dbID(id)))
		if err != nil {
			return err
		}
		value.RevokedAt = &at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		return affected(q.OAuthUpdateAccessTokenJSON(ctx, db.OAuthUpdateAccessTokenJSONParams{ID: dbID(id), DataJson: data}))
	})
}

// RevokeOAuthRefreshFamily revokes every token in the refresh-token family
// and the access tokens of the grants the family descends from, the
// fail-safe response to detected refresh token reuse: the thief's already-
// minted access token must die with the family, not survive until expiry.
func (s *Store) RevokeOAuthRefreshFamily(ctx context.Context, familyID credbound.UUID, at time.Time, commit credbound.Commit) error {
	return s.oauthMutate(ctx, commit, func(_ *sql.Tx, q *db.Queries) error {
		grantIDs, err := q.OAuthRefreshFamilyGrantIDs(ctx, dbID(familyID))
		if err != nil {
			return mapError(err)
		}
		if len(grantIDs) == 0 {
			return credbound.ErrNotFound
		}
		if _, err := q.OAuthRevokeRefreshFamily(ctx, db.OAuthRevokeRefreshFamilyParams{FamilyID: dbID(familyID), RevokedAt: nullableTime(&at)}); err != nil {
			return mapError(err)
		}
		for _, grantID := range grantIDs {
			if err := s.revokeOAuthAccessTokens(ctx, q, domainID(grantID), at); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) revokeOAuthGrantIDs(ctx context.Context, q *db.Queries, at time.Time, ids []credbound.UUID) error {
	for _, id := range ids {
		if err := s.revokeOAuthGrant(ctx, q, id, at); err != nil {
			return err
		}
	}
	return nil
}

// revokeOAuthGrantsByUser and its siblings push the filter into SQL against the
// indexed columns instead of scanning and JSON-decoding the whole table. The
// reset and anonymize paths reach this inside the audit-committing transaction,
// so a full-table scan there is a denial-of-service amplifier.
func (s *Store) revokeOAuthGrantsByUser(ctx context.Context, q *db.Queries, at time.Time, userID credbound.UUID) error {
	dbIDs, err := q.OAuthGrantIDsByUser(ctx, dbID(userID))
	if err != nil {
		return mapError(err)
	}
	ids := make([]credbound.UUID, 0, len(dbIDs))
	for _, id := range dbIDs {
		ids = append(ids, domainID(id))
	}
	return s.revokeOAuthGrantIDs(ctx, q, at, ids)
}

func (s *Store) revokeOAuthGrantsByClient(ctx context.Context, q *db.Queries, at time.Time, clientRecordID credbound.UUID) error {
	dbIDs, err := q.OAuthGrantIDsByClient(ctx, dbID(clientRecordID))
	if err != nil {
		return mapError(err)
	}
	ids := make([]credbound.UUID, 0, len(dbIDs))
	for _, id := range dbIDs {
		ids = append(ids, domainID(id))
	}
	return s.revokeOAuthGrantIDs(ctx, q, at, ids)
}

func (s *Store) revokeOAuthGrantsByResource(ctx context.Context, q *db.Queries, at time.Time, resourceID credbound.UUID) error {
	dbIDs, err := q.OAuthGrantIDsByResource(ctx, dbID(resourceID))
	if err != nil {
		return mapError(err)
	}
	ids := make([]credbound.UUID, 0, len(dbIDs))
	for _, id := range dbIDs {
		ids = append(ids, domainID(id))
	}
	return s.revokeOAuthGrantIDs(ctx, q, at, ids)
}

// revokeOAuthGrantsByIssuer has no indexed column to filter on (issuer id lives
// only in the JSON payload), so it scans. It runs only when an entire issuer is
// deleted, a rare root-level administrative operation.
func (s *Store) revokeOAuthGrantsByIssuer(ctx context.Context, q *db.Queries, at time.Time, issuerID credbound.UUID) error {
	records, err := q.OAuthGrantRecords(ctx)
	if err != nil {
		return mapError(err)
	}
	var ids []credbound.UUID
	for _, record := range records {
		grant, err := oauthDecode[credbound.OAuthGrant](record.DataJson)
		if err != nil {
			return err
		}
		if grant.IssuerID == issuerID {
			ids = append(ids, domainID(record.ID))
		}
	}
	return s.revokeOAuthGrantIDs(ctx, q, at, ids)
}

func (s *Store) revokeOAuthGrant(ctx context.Context, q *db.Queries, id credbound.UUID, at time.Time) error {
	grant, err := oauthDecodeQuery[credbound.OAuthGrant](q.OAuthGrantJSONByID(ctx, dbID(id)))
	if err != nil {
		return err
	}
	grant.RevokedAt, grant.UpdatedAt = &at, at
	data, err := oauthJSON(grant)
	if err != nil {
		return err
	}
	if err := affected(q.OAuthUpdateGrantJSON(ctx, db.OAuthUpdateGrantJSONParams{ID: dbID(id), DataJson: data})); err != nil {
		return err
	}
	if err := s.revokeOAuthAccessTokens(ctx, q, id, at); err != nil {
		return err
	}
	records, err := q.OAuthRefreshTokenRecordsByGrant(ctx, dbID(id))
	if err != nil {
		return mapError(err)
	}
	for _, record := range records {
		value, err := oauthDecode[credbound.OAuthRefreshToken](record.DataJson)
		if err != nil {
			return err
		}
		value.RevokedAt = &at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		if err := affected(q.OAuthRevokeRefreshToken(ctx, db.OAuthRevokeRefreshTokenParams{ID: record.ID, RevokedAt: nullableTime(&at), DataJson: data})); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) revokeOAuthAccessTokens(ctx context.Context, q *db.Queries, grantID credbound.UUID, at time.Time) error {
	records, err := q.OAuthAccessTokenRecordsByGrant(ctx, dbID(grantID))
	if err != nil {
		return mapError(err)
	}
	for _, record := range records {
		value, err := oauthDecode[credbound.OAuthAccessToken](record.DataJson)
		if err != nil {
			return err
		}
		if value.RevokedAt != nil {
			continue
		}
		value.RevokedAt = &at
		data, err := oauthJSON(value)
		if err != nil {
			return err
		}
		if err := affected(q.OAuthUpdateAccessTokenJSON(ctx, db.OAuthUpdateAccessTokenJSONParams{ID: record.ID, DataJson: data})); err != nil {
			return err
		}
	}
	return nil
}

// oauthFilter is an optional equality clause on one of a record table's uuid
// columns; an empty value means the caller did not filter on it.
type oauthFilter struct {
	column string
	value  string
}

// oauthPage streams one cursor page of an OAuth record table. table and the
// filter columns are package constants, never caller input; only the values
// are bound. Clauses are added when they apply rather than guarded in SQL, so
// each shape stays indexable.
func oauthPage[T any](s *Store, ctx context.Context, table string, filters []oauthFilter, page credbound.PageRequest, public func(T) T) iter.Seq2[credbound.PageEvent[T], error] {
	return func(yield func(credbound.PageEvent[T], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			var zero credbound.PageEvent[T]
			yield(zero, err)
			return
		}
		query := "SELECT data_json, created_at, id FROM " + table
		var args []any
		var clauses []string
		for _, filter := range filters {
			if filter.value == "" {
				continue
			}
			args = append(args, filter.value)
			clauses = append(clauses, fmt.Sprintf("%s = $%d::uuid", filter.column, len(args)))
		}
		if cursor.ID != (credbound.UUID{}) {
			args = append(args, cursor.Time, cursor.ID)
			clauses = append(clauses, fmt.Sprintf("(created_at, id) < ($%d, $%d::uuid)", len(args)-1, len(args)))
		}
		if len(clauses) > 0 {
			query += "\nWHERE " + strings.Join(clauses, " AND ")
		}
		args = append(args, page.Limit+1)
		query += fmt.Sprintf("\nORDER BY created_at DESC, id DESC LIMIT $%d", len(args))
		rows, err := s.query(streamCtx, query, args...)
		if err != nil {
			var zero credbound.PageEvent[T]
			yield(zero, mapError(err))
			return
		}
		defer rows.Close()
		var lastAt time.Time
		var lastID credbound.UUID
		count := 0
		for rows.Next() {
			var value T
			var raw []byte
			var createdAt time.Time
			var id credbound.UUID
			if err := rows.Scan(&raw, &createdAt, &id); err != nil {
				var zero credbound.PageEvent[T]
				yield(zero, err)
				return
			}
			if err := json.Unmarshal(raw, &value); err != nil {
				var zero credbound.PageEvent[T]
				yield(zero, fmt.Errorf("decode OAuth list item: %w", err))
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[T](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(lastAt, lastID)}), nil)
				return
			}
			lastAt, lastID, count = createdAt, id, count+1
			if !yield(credbound.ItemEvent(public(value)), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			var zero credbound.PageEvent[T]
			yield(zero, err)
			return
		}
		yield(credbound.EndEvent[T](credbound.PageEnd{}), nil)
	}
}

func (s *Store) oauthMutate(ctx context.Context, commit credbound.Commit, fn func(*sql.Tx, *db.Queries) error) error {
	// OAuth writes append to the singleton audit chain and run read-then-write
	// invariant checks (the DCR registration count). Both rest on row locks
	// taken inside the callback, so mutations run concurrently.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return mapError(err)
	}
	defer tx.Rollback()
	q := s.queries.WithTx(tx)
	if err := fn(tx, q); err != nil {
		return err
	}
	if commit.Transactional != nil {
		handle := newTx(tx, commit.Audit)
		err = commit.Transactional(ctx, handle)
		handle.close()
		if err != nil {
			return err
		}
	}
	if err := chainAudit(ctx, q, commit.Audit); err != nil {
		return err
	}
	return mapError(tx.Commit())
}

func oauthDecodeQuery[T any](raw any, err error) (T, error) {
	var value T
	if err != nil {
		return value, mapError(err)
	}
	return oauthDecode[T](raw)
}

func oauthDecode[T any](raw any) (T, error) {
	var value T
	var encoded []byte
	switch typed := raw.(type) {
	case string:
		encoded = []byte(typed)
	case json.RawMessage:
		encoded = typed
	case []byte:
		encoded = typed
	default:
		return value, fmt.Errorf("decode OAuth record: unsupported JSON type %T", raw)
	}
	if err := json.Unmarshal(encoded, &value); err != nil {
		return value, fmt.Errorf("decode OAuth record: %w", err)
	}
	return value, nil
}

func insertOAuthAccessToken(ctx context.Context, q *db.Queries, value credbound.OAuthAccessToken) error {
	data, err := oauthJSON(value)
	if err != nil {
		return err
	}
	return mapError(q.OAuthInsertAccessToken(ctx, db.OAuthInsertAccessTokenParams{ID: dbID(value.ID), Prefix: value.Prefix, GrantID: dbID(value.GrantID), DataJson: data}))
}

func insertOAuthRefreshToken(ctx context.Context, q *db.Queries, value credbound.OAuthRefreshToken) error {
	data, err := oauthJSON(value)
	if err != nil {
		return err
	}
	return mapError(q.OAuthInsertRefreshToken(ctx, db.OAuthInsertRefreshTokenParams{
		ID: dbID(value.ID), FamilyID: dbID(value.FamilyID), Prefix: value.Prefix, GrantID: dbID(value.GrantID), UsedAt: nullableTime(value.UsedAt), RevokedAt: nullableTime(value.RevokedAt), ExpiresAt: value.ExpiresAt, DataJson: data,
	}))
}

func oauthJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal oauth record: %w", err)
	}
	return raw, nil
}

var _ credbound.OAuthStore = (*Store)(nil)
