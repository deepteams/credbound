package memory

import (
	"context"
	"iter"
	"slices"
	"sort"
	"time"

	"github.com/deepteams/credbound"
)

// CreateOAuthIssuer stores an authorization server issuer; a duplicate ID or
// URL reports credbound.ErrConflict.
func (s *Store) CreateOAuthIssuer(ctx context.Context, issuer credbound.OAuthIssuer, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthIssuers[issuer.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthIssuerURLs[issuer.Issuer]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthIssuers[issuer.ID] = cloneOAuthIssuer(issuer)
	s.oauthIssuerURLs[issuer.Issuer] = issuer.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// UpdateOAuthIssuer persists the issuer's mutable attributes.
func (s *Store) UpdateOAuthIssuer(ctx context.Context, issuer credbound.OAuthIssuer, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.oauthIssuers[issuer.ID]
	if !ok || current.Issuer != issuer.Issuer {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthIssuers[issuer.ID] = cloneOAuthIssuer(issuer)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SetOAuthIssuerDisabled enables or disables the issuer.
func (s *Store) SetOAuthIssuerDisabled(ctx context.Context, issuerID string, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	issuer, ok := s.oauthIssuers[issuerID]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	issuer.DisabledAt = nil
	if disabled {
		issuer.DisabledAt = cloneTime(&at)
	}
	issuer.UpdatedAt = at
	s.oauthIssuers[issuerID] = cloneOAuthIssuer(issuer)
	if disabled {
		for id, grant := range s.oauthGrants {
			if grant.IssuerID == issuerID {
				s.revokeOAuthGrantLocked(id, at)
			}
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthIssuerByID returns the issuer with the given ID.
func (s *Store) OAuthIssuerByID(ctx context.Context, id string) (credbound.OAuthIssuer, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthIssuer{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.oauthIssuers[id]
	if !ok {
		return credbound.OAuthIssuer{}, credbound.ErrNotFound
	}
	return cloneOAuthIssuer(value), nil
}

// OAuthIssuerByURL resolves an issuer by its canonical URL.
func (s *Store) OAuthIssuerByURL(ctx context.Context, raw string) (credbound.OAuthIssuer, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthIssuer{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthIssuerURLs[raw]
	if !ok {
		return credbound.OAuthIssuer{}, credbound.ErrNotFound
	}
	return cloneOAuthIssuer(s.oauthIssuers[id]), nil
}

// OAuthIssuers streams all issuers, newest first, as one cursor page.
func (s *Store) OAuthIssuers(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthIssuer], error] {
	return func(yield func(credbound.PageEvent[credbound.OAuthIssuer], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.OAuthIssuer]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.OAuthIssuer]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.OAuthIssuer, 0, len(s.oauthIssuers))
		for _, value := range s.oauthIssuers {
			if afterCursor(value.CreatedAt, value.ID, cursor) {
				values = append(values, cloneOAuthIssuer(value))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.OAuthIssuer) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

// CreateOAuthProtectedResource stores a protected resource; a duplicate ID
// or URI reports credbound.ErrConflict.
func (s *Store) CreateOAuthProtectedResource(ctx context.Context, resource credbound.OAuthProtectedResource, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthIssuers[resource.IssuerID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.workspaces[resource.WorkspaceID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.oauthResources[resource.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthResourceURIs[resource.Resource]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthResources[resource.ID] = cloneOAuthResource(resource)
	s.oauthResourceURIs[resource.Resource] = resource.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// SetOAuthProtectedResourceDisabled enables or disables the resource.
func (s *Store) SetOAuthProtectedResourceDisabled(ctx context.Context, resourceID string, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	resource, ok := s.oauthResources[resourceID]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	resource.DisabledAt = nil
	if disabled {
		resource.DisabledAt = cloneTime(&at)
	}
	resource.UpdatedAt = at
	s.oauthResources[resourceID] = cloneOAuthResource(resource)
	if disabled {
		for id, grant := range s.oauthGrants {
			if grant.ResourceID == resourceID {
				s.revokeOAuthGrantLocked(id, at)
			}
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthProtectedResourceByID returns the resource with the given ID.
func (s *Store) OAuthProtectedResourceByID(ctx context.Context, id string) (credbound.OAuthProtectedResource, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthProtectedResource{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.oauthResources[id]
	if !ok {
		return credbound.OAuthProtectedResource{}, credbound.ErrNotFound
	}
	return cloneOAuthResource(value), nil
}

// OAuthProtectedResourceByURI resolves a resource by its canonical URI.
func (s *Store) OAuthProtectedResourceByURI(ctx context.Context, uri string) (credbound.OAuthProtectedResource, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthProtectedResource{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthResourceURIs[uri]
	if !ok {
		return credbound.OAuthProtectedResource{}, credbound.ErrNotFound
	}
	return cloneOAuthResource(s.oauthResources[id]), nil
}

// OAuthProtectedResources streams resources, optionally filtered by
// workspace, newest first, as one cursor page.
func (s *Store) OAuthProtectedResources(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthProtectedResource], error] {
	return func(yield func(credbound.PageEvent[credbound.OAuthProtectedResource], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.OAuthProtectedResource]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.OAuthProtectedResource]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.OAuthProtectedResource, 0)
		for _, value := range s.oauthResources {
			if value.WorkspaceID == workspaceID && afterCursor(value.CreatedAt, value.ID, cursor) {
				values = append(values, cloneOAuthResource(value))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.OAuthProtectedResource) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

// CreateOAuthClient stores a dynamically registered client, consuming a use
// of the initial access token in the same commit when one gated the
// registration.
func (s *Store) CreateOAuthClient(ctx context.Context, client credbound.OAuthClient, initialAccessTokenID string, usedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	issuer, ok := s.oauthIssuers[client.IssuerID]
	if !ok {
		return credbound.ErrNotFound
	}
	if client.Source == credbound.OAuthClientDCR && issuer.DCRMode == credbound.OAuthDCROpen {
		active := 0
		for _, existing := range s.oauthClients {
			if existing.IssuerID == client.IssuerID && existing.Source == credbound.OAuthClientDCR && existing.DisabledAt == nil {
				active++
			}
		}
		if active >= issuer.DCROpenRegistrationLimit {
			return credbound.ErrConflict
		}
	}
	key := oauthClientKey(client.IssuerID, client.ClientID)
	if _, ok := s.oauthClients[client.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthClientKeys[key]; ok {
		return credbound.ErrConflict
	}
	var initial credbound.OAuthInitialAccessToken
	if initialAccessTokenID != "" {
		var ok bool
		initial, ok = s.oauthInitialTokens[initialAccessTokenID]
		if !ok || initial.IssuerID != client.IssuerID {
			return credbound.ErrNotFound
		}
		if initial.RevokedAt != nil || !usedAt.Before(initial.ExpiresAt) || initial.RegistrationCount >= initial.MaxRegistrations {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthClients[client.ID] = cloneOAuthClient(client)
	s.oauthClientKeys[key] = client.ID
	if initialAccessTokenID != "" {
		initial.RegistrationCount++
		s.oauthInitialTokens[initialAccessTokenID] = cloneOAuthInitialToken(initial)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// UpsertOAuthCIMDClient inserts or refreshes a client registered through a
// Client Identifier Metadata Document.
func (s *Store) UpsertOAuthCIMDClient(ctx context.Context, client credbound.OAuthClient, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthIssuers[client.IssuerID]; !ok {
		return credbound.ErrNotFound
	}
	key := oauthClientKey(client.IssuerID, client.ClientID)
	if id, ok := s.oauthClientKeys[key]; ok && id != client.ID {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthClients[client.ID] = cloneOAuthClient(client)
	s.oauthClientKeys[key] = client.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// SetOAuthClientDisabled enables or disables the client.
func (s *Store) SetOAuthClientDisabled(ctx context.Context, clientID string, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.oauthClients[clientID]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	client.DisabledAt = nil
	if disabled {
		client.DisabledAt = cloneTime(&at)
	}
	client.UpdatedAt = at
	s.oauthClients[clientID] = cloneOAuthClient(client)
	if disabled {
		for id, grant := range s.oauthGrants {
			if grant.ClientRecordID == clientID {
				s.revokeOAuthGrantLocked(id, at)
			}
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthClientByID returns the client with the given record ID.
func (s *Store) OAuthClientByID(ctx context.Context, id string) (credbound.OAuthClient, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthClient{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.oauthClients[id]
	if !ok {
		return credbound.OAuthClient{}, credbound.ErrNotFound
	}
	return cloneOAuthClient(value), nil
}

// OAuthClientByClientID resolves the issuer's client by its OAuth client_id.
func (s *Store) OAuthClientByClientID(ctx context.Context, issuerID, clientID string) (credbound.OAuthClient, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthClient{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthClientKeys[oauthClientKey(issuerID, clientID)]
	if !ok {
		return credbound.OAuthClient{}, credbound.ErrNotFound
	}
	return cloneOAuthClient(s.oauthClients[id]), nil
}

// OAuthClients streams the issuer's clients, newest first, as one cursor
// page.
func (s *Store) OAuthClients(ctx context.Context, issuerID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthClient], error] {
	return func(yield func(credbound.PageEvent[credbound.OAuthClient], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.OAuthClient]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.OAuthClient]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.OAuthClient, 0)
		for _, value := range s.oauthClients {
			if value.IssuerID == issuerID && afterCursor(value.CreatedAt, value.ID, cursor) {
				values = append(values, cloneOAuthClient(value))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		for index := range values {
			values[index].SecretDigest = nil
		}
		yieldMemoryPage(values, page.Limit, func(value credbound.OAuthClient) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

// CreateOAuthInitialAccessToken stores an initial access token for gated
// dynamic client registration.
func (s *Store) CreateOAuthInitialAccessToken(ctx context.Context, token credbound.OAuthInitialAccessToken, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthIssuers[token.IssuerID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.oauthInitialTokens[token.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthInitialKeys[token.Prefix]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthInitialTokens[token.ID] = cloneOAuthInitialToken(token)
	s.oauthInitialKeys[token.Prefix] = token.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthInitialAccessTokenByPrefix returns the token record addressed by its
// lookup prefix.
func (s *Store) OAuthInitialAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthInitialAccessToken, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthInitialAccessToken{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthInitialKeys[prefix]
	if !ok {
		return credbound.OAuthInitialAccessToken{}, credbound.ErrNotFound
	}
	return cloneOAuthInitialToken(s.oauthInitialTokens[id]), nil
}

// RevokeOAuthInitialAccessToken marks the token revoked.
func (s *Store) RevokeOAuthInitialAccessToken(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.oauthInitialTokens[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	token.RevokedAt = cloneTime(&at)
	s.oauthInitialTokens[id] = token
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateOAuthGrantAndCode atomically stores a user grant with its single-use
// authorization code.
func (s *Store) CreateOAuthGrantAndCode(ctx context.Context, grant credbound.OAuthGrant, code credbound.OAuthAuthorizationCode, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthClients[grant.ClientRecordID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.oauthResources[grant.ResourceID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.oauthGrants[grant.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthCodes[code.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthCodeKeys[code.Prefix]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthGrants[grant.ID] = cloneOAuthGrant(grant)
	s.oauthCodes[code.ID] = cloneOAuthCode(code)
	s.oauthCodeKeys[code.Prefix] = code.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthGrant returns the grant with the given ID.
func (s *Store) OAuthGrant(ctx context.Context, id string) (credbound.OAuthGrant, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthGrant{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.oauthGrants[id]
	if !ok {
		return credbound.OAuthGrant{}, credbound.ErrNotFound
	}
	return cloneOAuthGrant(value), nil
}

// RevokeOAuthGrant revokes the grant together with its outstanding access
// and refresh tokens.
func (s *Store) RevokeOAuthGrant(ctx context.Context, grantID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthGrants[grantID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.revokeOAuthGrantLocked(grantID, at)
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthGrants streams grants, optionally filtered by user and workspace,
// newest first, as one cursor page.
func (s *Store) OAuthGrants(ctx context.Context, userID, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.OAuthGrant], error] {
	return func(yield func(credbound.PageEvent[credbound.OAuthGrant], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.OAuthGrant]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.OAuthGrant]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.OAuthGrant, 0)
		for _, value := range s.oauthGrants {
			if (userID == "" || value.UserID == userID) && (workspaceID == "" || value.WorkspaceID == workspaceID) && afterCursor(value.CreatedAt, value.ID, cursor) {
				values = append(values, cloneOAuthGrant(value))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.OAuthGrant) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

func (s *Store) revokeOAuthGrantLocked(grantID string, at time.Time) {
	grant, ok := s.oauthGrants[grantID]
	if !ok {
		return
	}
	grant.RevokedAt = cloneTime(&at)
	grant.UpdatedAt = at
	s.oauthGrants[grantID] = cloneOAuthGrant(grant)
	for id, token := range s.oauthAccessTokens {
		if token.GrantID == grantID && token.RevokedAt == nil {
			token.RevokedAt = cloneTime(&at)
			s.oauthAccessTokens[id] = cloneOAuthAccessToken(token)
		}
	}
	for id, token := range s.oauthRefreshTokens {
		if token.GrantID == grantID && token.RevokedAt == nil {
			token.RevokedAt = cloneTime(&at)
			s.oauthRefreshTokens[id] = cloneOAuthRefreshToken(token)
		}
	}
}

// OAuthAuthorizationCodeByPrefix returns the authorization code record
// addressed by its lookup prefix.
func (s *Store) OAuthAuthorizationCodeByPrefix(ctx context.Context, prefix string) (credbound.OAuthAuthorizationCode, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthAuthorizationCode{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthCodeKeys[prefix]
	if !ok {
		return credbound.OAuthAuthorizationCode{}, credbound.ErrNotFound
	}
	return cloneOAuthCode(s.oauthCodes[id]), nil
}

// ConsumeOAuthAuthorizationCode atomically marks the single-use code
// consumed and stores the access and optional refresh token it was exchanged
// for.
func (s *Store) ConsumeOAuthAuthorizationCode(ctx context.Context, codeID string, usedAt time.Time, access credbound.OAuthAccessToken, refresh *credbound.OAuthRefreshToken, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.oauthCodes[codeID]
	if !ok {
		return credbound.ErrNotFound
	}
	if code.UsedAt != nil || !usedAt.Before(code.ExpiresAt) {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthAccessKeys[access.Prefix]; ok {
		return credbound.ErrConflict
	}
	if refresh != nil {
		if _, ok := s.oauthRefreshKeys[refresh.Prefix]; ok {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	code.UsedAt = cloneTime(&usedAt)
	s.oauthCodes[codeID] = code
	s.oauthAccessTokens[access.ID] = cloneOAuthAccessToken(access)
	s.oauthAccessKeys[access.Prefix] = access.ID
	if refresh != nil {
		s.oauthRefreshTokens[refresh.ID] = cloneOAuthRefreshToken(*refresh)
		s.oauthRefreshKeys[refresh.Prefix] = refresh.ID
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthAccessTokenByPrefix returns the access token record addressed by its
// lookup prefix.
func (s *Store) OAuthAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthAccessToken, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthAccessToken{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthAccessKeys[prefix]
	if !ok {
		return credbound.OAuthAccessToken{}, credbound.ErrNotFound
	}
	return cloneOAuthAccessToken(s.oauthAccessTokens[id]), nil
}

func cloneOAuthClientAccessToken(v credbound.OAuthClientAccessToken) credbound.OAuthClientAccessToken {
	v.Digest = slices.Clone(v.Digest)
	v.Scopes = slices.Clone(v.Scopes)
	return v
}

// CreateOAuthClientAccessToken stores a client-credentials access token.
func (s *Store) CreateOAuthClientAccessToken(ctx context.Context, value credbound.OAuthClientAccessToken, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.oauthClientTokenKeys[value.Prefix]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.oauthClientTokens[value.ID] = cloneOAuthClientAccessToken(value)
	s.oauthClientTokenKeys[value.Prefix] = value.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// OAuthClientAccessTokenByPrefix returns the client-credentials access token
// addressed by its lookup prefix.
func (s *Store) OAuthClientAccessTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthClientAccessToken, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthClientAccessToken{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthClientTokenKeys[prefix]
	if !ok {
		return credbound.OAuthClientAccessToken{}, credbound.ErrNotFound
	}
	return cloneOAuthClientAccessToken(s.oauthClientTokens[id]), nil
}

// OAuthRefreshTokenByPrefix returns the refresh token record addressed by
// its lookup prefix.
func (s *Store) OAuthRefreshTokenByPrefix(ctx context.Context, prefix string) (credbound.OAuthRefreshToken, error) {
	if err := ctx.Err(); err != nil {
		return credbound.OAuthRefreshToken{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.oauthRefreshKeys[prefix]
	if !ok {
		return credbound.OAuthRefreshToken{}, credbound.ErrNotFound
	}
	return cloneOAuthRefreshToken(s.oauthRefreshTokens[id]), nil
}

// RotateOAuthRefreshToken atomically retires the used refresh token and
// stores its successor pair, keeping the family linked for reuse detection.
func (s *Store) RotateOAuthRefreshToken(ctx context.Context, previousID string, usedAt time.Time, access credbound.OAuthAccessToken, refresh credbound.OAuthRefreshToken, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previousToken, ok := s.oauthRefreshTokens[previousID]
	if !ok {
		return credbound.ErrNotFound
	}
	if previousToken.UsedAt != nil || previousToken.RevokedAt != nil || !usedAt.Before(previousToken.ExpiresAt) {
		return credbound.ErrConflict
	}
	if previousToken.FamilyID != refresh.FamilyID || previousToken.GrantID != refresh.GrantID {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthAccessKeys[access.Prefix]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.oauthRefreshKeys[refresh.Prefix]; ok {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	previousToken.UsedAt = cloneTime(&usedAt)
	previousToken.ReplacedByID = refresh.ID
	s.oauthRefreshTokens[previousID] = previousToken
	s.oauthAccessTokens[access.ID] = cloneOAuthAccessToken(access)
	s.oauthAccessKeys[access.Prefix] = access.ID
	s.oauthRefreshTokens[refresh.ID] = cloneOAuthRefreshToken(refresh)
	s.oauthRefreshKeys[refresh.Prefix] = refresh.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeOAuthAccessToken marks the access token revoked.
func (s *Store) RevokeOAuthAccessToken(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.oauthAccessTokens[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if token.RevokedAt == nil {
		token.RevokedAt = cloneTime(&at)
		s.oauthAccessTokens[id] = token
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeOAuthRefreshFamily revokes every token in the refresh-token family,
// the fail-safe response to detected refresh token reuse.
func (s *Store) RevokeOAuthRefreshFamily(ctx context.Context, familyID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, token := range s.oauthRefreshTokens {
		if token.FamilyID == familyID {
			found = true
			break
		}
	}
	if !found {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	for id, token := range s.oauthRefreshTokens {
		if token.FamilyID == familyID && token.RevokedAt == nil {
			token.RevokedAt = cloneTime(&at)
			s.oauthRefreshTokens[id] = token
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

func oauthClientKey(issuerID, clientID string) string { return issuerID + "\x00" + clientID }

func cloneOAuthIssuer(v credbound.OAuthIssuer) credbound.OAuthIssuer {
	v.CIMDAllowedOrigins = slices.Clone(v.CIMDAllowedOrigins)
	v.DisabledAt = cloneTime(v.DisabledAt)
	return v
}
func cloneOAuthResource(v credbound.OAuthProtectedResource) credbound.OAuthProtectedResource {
	v.Scopes = slices.Clone(v.Scopes)
	for i := range v.Scopes {
		v.Scopes[i].Permissions = slices.Clone(v.Scopes[i].Permissions)
	}
	v.DisabledAt = cloneTime(v.DisabledAt)
	return v
}
func cloneOAuthClient(v credbound.OAuthClient) credbound.OAuthClient {
	v.RedirectURIs = slices.Clone(v.RedirectURIs)
	v.GrantTypes = slices.Clone(v.GrantTypes)
	v.ResponseTypes = slices.Clone(v.ResponseTypes)
	v.Scopes = slices.Clone(v.Scopes)
	v.JWKS = slices.Clone(v.JWKS)
	v.SecretDigest = slices.Clone(v.SecretDigest)
	v.MetadataHash = slices.Clone(v.MetadataHash)
	v.MetadataExpiresAt = cloneTime(v.MetadataExpiresAt)
	v.DisabledAt = cloneTime(v.DisabledAt)
	return v
}
func cloneOAuthInitialToken(v credbound.OAuthInitialAccessToken) credbound.OAuthInitialAccessToken {
	v.Digest = slices.Clone(v.Digest)
	v.RevokedAt = cloneTime(v.RevokedAt)
	return v
}
func cloneOAuthGrant(v credbound.OAuthGrant) credbound.OAuthGrant {
	v.Scopes = slices.Clone(v.Scopes)
	v.MetadataHash = slices.Clone(v.MetadataHash)
	v.RevokedAt = cloneTime(v.RevokedAt)
	return v
}
func cloneOAuthCode(v credbound.OAuthAuthorizationCode) credbound.OAuthAuthorizationCode {
	v.Digest = slices.Clone(v.Digest)
	v.Scopes = slices.Clone(v.Scopes)
	v.UsedAt = cloneTime(v.UsedAt)
	return v
}
func cloneOAuthAccessToken(v credbound.OAuthAccessToken) credbound.OAuthAccessToken {
	v.Digest = slices.Clone(v.Digest)
	v.Scopes = slices.Clone(v.Scopes)
	v.RevokedAt = cloneTime(v.RevokedAt)
	return v
}
func cloneOAuthRefreshToken(v credbound.OAuthRefreshToken) credbound.OAuthRefreshToken {
	v.Digest = slices.Clone(v.Digest)
	v.Scopes = slices.Clone(v.Scopes)
	v.UsedAt = cloneTime(v.UsedAt)
	v.RevokedAt = cloneTime(v.RevokedAt)
	return v
}
