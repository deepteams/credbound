package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestOAuthStoreHonorsCanceledContext(t *testing.T) {
	store := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	commit := credbound.Commit{}
	issuer := credbound.OAuthIssuer{}
	resource := credbound.OAuthProtectedResource{}
	client := credbound.OAuthClient{}
	initial := credbound.OAuthInitialAccessToken{}
	grant := credbound.OAuthGrant{}
	code := credbound.OAuthAuthorizationCode{}
	access := credbound.OAuthAccessToken{}
	refresh := credbound.OAuthRefreshToken{}
	calls := []func() error{
		func() error { return store.CreateOAuthIssuer(ctx, issuer, commit) },
		func() error { return store.UpdateOAuthIssuer(ctx, issuer, commit) },
		func() error { return store.SetOAuthIssuerDisabled(ctx, credbound.UUID{}, true, time.Time{}, commit) },
		func() error { _, err := store.OAuthIssuerByID(ctx, credbound.UUID{}); return err },
		func() error { _, err := store.OAuthIssuerByURL(ctx, ""); return err },
		func() error { return store.CreateOAuthProtectedResource(ctx, resource, commit) },
		func() error {
			return store.SetOAuthProtectedResourceDisabled(ctx, credbound.UUID{}, true, time.Time{}, commit)
		},
		func() error { _, err := store.OAuthProtectedResourceByID(ctx, credbound.UUID{}); return err },
		func() error { _, err := store.OAuthProtectedResourceByURI(ctx, ""); return err },
		func() error { return store.CreateOAuthClient(ctx, client, credbound.UUID{}, time.Time{}, commit) },
		func() error { return store.UpsertOAuthCIMDClient(ctx, client, commit) },
		func() error { return store.SetOAuthClientDisabled(ctx, credbound.UUID{}, true, time.Time{}, commit) },
		func() error { _, err := store.OAuthClientByID(ctx, credbound.UUID{}); return err },
		func() error { _, err := store.OAuthClientByClientID(ctx, credbound.UUID{}, ""); return err },
		func() error { return store.CreateOAuthInitialAccessToken(ctx, initial, commit) },
		func() error { _, err := store.OAuthInitialAccessTokenByPrefix(ctx, ""); return err },
		func() error { return store.RevokeOAuthInitialAccessToken(ctx, credbound.UUID{}, time.Time{}, commit) },
		func() error { return store.CreateOAuthGrantAndCode(ctx, grant, code, commit) },
		func() error { _, err := store.OAuthGrant(ctx, credbound.UUID{}); return err },
		func() error { return store.RevokeOAuthGrant(ctx, credbound.UUID{}, time.Time{}, commit) },
		func() error { _, err := store.OAuthAuthorizationCodeByPrefix(ctx, ""); return err },
		func() error {
			return store.ConsumeOAuthAuthorizationCode(ctx, credbound.UUID{}, time.Time{}, access, &refresh, commit)
		},
		func() error { _, err := store.OAuthAccessTokenByPrefix(ctx, ""); return err },
		func() error { _, err := store.OAuthRefreshTokenByPrefix(ctx, ""); return err },
		func() error {
			return store.RotateOAuthRefreshToken(ctx, credbound.UUID{}, time.Time{}, access, refresh, commit)
		},
		func() error { return store.RevokeOAuthAccessToken(ctx, credbound.UUID{}, time.Time{}, commit) },
		func() error { return store.RevokeOAuthRefreshFamily(ctx, credbound.UUID{}, time.Time{}, commit) },
	}
	for index, call := range calls {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("call %d = %v", index, err)
		}
	}
	assertSequenceError(t, store.OAuthIssuers(ctx, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthProtectedResources(ctx, credbound.UUID{}, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthClients(ctx, credbound.UUID{}, credbound.PageRequest{Limit: 50}), context.Canceled)
	assertSequenceError(t, store.OAuthGrants(ctx, credbound.UUID{}, credbound.UUID{}, credbound.PageRequest{Limit: 50}), context.Canceled)
}

func TestOAuthStoreRejectsBrokenReferencesAndReplay(t *testing.T) {
	store := New()
	ctx := context.Background()
	now := time.Now().UTC()
	commit := credbound.Commit{}
	badPage := credbound.PageRequest{Cursor: "%%%", Limit: 50}
	assertSequenceError(t, store.OAuthIssuers(ctx, badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthProtectedResources(ctx, credbound.UUID{}, badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthClients(ctx, credbound.UUID{}, badPage), credbound.ErrInvalidInput)
	assertSequenceError(t, store.OAuthGrants(ctx, credbound.UUID{}, credbound.UUID{}, badPage), credbound.ErrInvalidInput)
	want := func(name string, err, target error) {
		t.Helper()
		if !errors.Is(err, target) {
			t.Fatalf("%s = %v, want %v", name, err, target)
		}
	}
	_, err := store.OAuthIssuerByID(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"))
	want("missing issuer id", err, credbound.ErrNotFound)
	_, err = store.OAuthIssuerByURL(ctx, "missing")
	want("missing issuer URL", err, credbound.ErrNotFound)
	_, err = store.OAuthProtectedResourceByID(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"))
	want("missing resource id", err, credbound.ErrNotFound)
	_, err = store.OAuthProtectedResourceByURI(ctx, "missing")
	want("missing resource URI", err, credbound.ErrNotFound)
	_, err = store.OAuthClientByID(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"))
	want("missing client id", err, credbound.ErrNotFound)
	_, err = store.OAuthClientByClientID(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), "missing")
	want("missing client key", err, credbound.ErrNotFound)
	_, err = store.OAuthInitialAccessTokenByPrefix(ctx, "missing")
	want("missing initial prefix", err, credbound.ErrNotFound)
	_, err = store.OAuthGrant(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"))
	want("missing grant", err, credbound.ErrNotFound)
	_, err = store.OAuthAuthorizationCodeByPrefix(ctx, "missing")
	want("missing code", err, credbound.ErrNotFound)
	_, err = store.OAuthAccessTokenByPrefix(ctx, "missing")
	want("missing access", err, credbound.ErrNotFound)
	_, err = store.OAuthRefreshTokenByPrefix(ctx, "missing")
	want("missing refresh", err, credbound.ErrNotFound)
	issuer := credbound.OAuthIssuer{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-535c6f8eb511"), Issuer: "https://auth.example.com"}
	store.oauthIssuers[issuer.ID] = issuer
	store.oauthIssuerURLs[issuer.Issuer] = issuer.ID
	want("duplicate issuer id", store.CreateOAuthIssuer(ctx, issuer, commit), credbound.ErrConflict)
	want("duplicate issuer URL", store.CreateOAuthIssuer(ctx, credbound.OAuthIssuer{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), Issuer: issuer.Issuer}, commit), credbound.ErrConflict)
	want("missing issuer update", store.UpdateOAuthIssuer(ctx, credbound.OAuthIssuer{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, commit), credbound.ErrNotFound)

	resource := credbound.OAuthProtectedResource{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-5de95319f174"), IssuerID: issuer.ID, WorkspaceID: credbound.MustParseUUID("0198b463-0000-7000-8000-21a3230e0377"), Resource: "https://mcp.example.com"}
	want("missing resource issuer", store.CreateOAuthProtectedResource(ctx, credbound.OAuthProtectedResource{IssuerID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, commit), credbound.ErrNotFound)
	want("missing resource workspace", store.CreateOAuthProtectedResource(ctx, resource, commit), credbound.ErrNotFound)
	store.workspaces[resource.WorkspaceID] = credbound.Workspace{ID: resource.WorkspaceID}
	store.oauthResources[resource.ID] = resource
	store.oauthResourceURIs[resource.Resource] = resource.ID
	want("duplicate resource id", store.CreateOAuthProtectedResource(ctx, resource, commit), credbound.ErrConflict)
	want("duplicate resource URI", store.CreateOAuthProtectedResource(ctx, credbound.OAuthProtectedResource{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, WorkspaceID: resource.WorkspaceID, Resource: resource.Resource}, commit), credbound.ErrConflict)

	client := credbound.OAuthClient{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-948fe603f61d"), IssuerID: issuer.ID, ClientID: "client-id"}
	want("missing client issuer", store.CreateOAuthClient(ctx, credbound.OAuthClient{IssuerID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, credbound.UUID{}, now, commit), credbound.ErrNotFound)
	store.oauthClients[client.ID] = client
	store.oauthClientKeys[oauthClientKey(client.IssuerID, client.ClientID)] = client.ID
	want("duplicate client id", store.CreateOAuthClient(ctx, client, credbound.UUID{}, now, commit), credbound.ErrConflict)
	want("duplicate client key", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, ClientID: client.ClientID}, credbound.UUID{}, now, commit), credbound.ErrConflict)
	want("missing CIMD issuer", store.UpsertOAuthCIMDClient(ctx, credbound.OAuthClient{IssuerID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, commit), credbound.ErrNotFound)
	want("conflicting CIMD", store.UpsertOAuthCIMDClient(ctx, credbound.OAuthClient{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, ClientID: client.ClientID}, commit), credbound.ErrConflict)

	initial := credbound.OAuthInitialAccessToken{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-ac1b5c0961a7"), IssuerID: issuer.ID, Prefix: "prefix", MaxRegistrations: 1, ExpiresAt: now.Add(time.Hour)}
	want("missing initial issuer", store.CreateOAuthInitialAccessToken(ctx, credbound.OAuthInitialAccessToken{IssuerID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, commit), credbound.ErrNotFound)
	store.oauthInitialTokens[initial.ID] = initial
	store.oauthInitialKeys[initial.Prefix] = initial.ID
	want("duplicate initial id", store.CreateOAuthInitialAccessToken(ctx, initial, commit), credbound.ErrConflict)
	want("duplicate initial prefix", store.CreateOAuthInitialAccessToken(ctx, credbound.OAuthInitialAccessToken{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, Prefix: initial.Prefix}, commit), credbound.ErrConflict)
	want("missing initial reference", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, ClientID: "other"}, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, commit), credbound.ErrNotFound)
	initial.RegistrationCount = 1
	store.oauthInitialTokens[initial.ID] = initial
	want("exhausted initial", store.CreateOAuthClient(ctx, credbound.OAuthClient{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), IssuerID: issuer.ID, ClientID: "other"}, initial.ID, now, commit), credbound.ErrConflict)
	want("missing initial revoke", store.RevokeOAuthInitialAccessToken(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, commit), credbound.ErrNotFound)

	grant := credbound.OAuthGrant{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-3492ad65d05a"), ClientRecordID: client.ID, ResourceID: resource.ID}
	code := credbound.OAuthAuthorizationCode{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-5694d08a2e53"), Prefix: "code-prefix", GrantID: grant.ID, ExpiresAt: now.Add(time.Hour)}
	want("missing grant client", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ClientRecordID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, code, commit), credbound.ErrNotFound)
	want("missing grant resource", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ClientRecordID: client.ID, ResourceID: credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6")}, code, commit), credbound.ErrNotFound)
	store.oauthGrants[grant.ID] = grant
	store.oauthCodes[code.ID] = code
	store.oauthCodeKeys[code.Prefix] = code.ID
	want("duplicate grant", store.CreateOAuthGrantAndCode(ctx, grant, credbound.OAuthAuthorizationCode{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0")}, commit), credbound.ErrConflict)
	want("duplicate code", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), ClientRecordID: client.ID, ResourceID: resource.ID}, code, commit), credbound.ErrConflict)
	want("duplicate code prefix", store.CreateOAuthGrantAndCode(ctx, credbound.OAuthGrant{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), ClientRecordID: client.ID, ResourceID: resource.ID}, credbound.OAuthAuthorizationCode{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0"), Prefix: code.Prefix}, commit), credbound.ErrConflict)
	want("missing code consume", store.ConsumeOAuthAuthorizationCode(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, credbound.OAuthAccessToken{}, nil, commit), credbound.ErrNotFound)
	used := now
	code.UsedAt = &used
	store.oauthCodes[code.ID] = code
	want("code replay", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{}, nil, commit), credbound.ErrConflict)
	code.UsedAt = nil
	store.oauthCodes[code.ID] = code
	store.oauthAccessKeys["duplicate-access"] = credbound.MustParseUUID("0198b463-0000-7000-8000-a0561fd649cd")
	want("duplicate access prefix", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{Prefix: "duplicate-access"}, nil, commit), credbound.ErrConflict)
	delete(store.oauthAccessKeys, "duplicate-access")
	store.oauthRefreshKeys["duplicate-refresh"] = credbound.MustParseUUID("0198b463-0000-7000-8000-d6cc0a088c07")
	want("duplicate refresh prefix", store.ConsumeOAuthAuthorizationCode(ctx, code.ID, now, credbound.OAuthAccessToken{}, &credbound.OAuthRefreshToken{Prefix: "duplicate-refresh"}, commit), credbound.ErrConflict)

	refresh := credbound.OAuthRefreshToken{ID: credbound.MustParseUUID("0198b463-0000-7000-8000-d6cc0a088c07"), FamilyID: credbound.MustParseUUID("0198b463-0000-7000-8000-d34a569ab7aa"), Prefix: "refresh-prefix", GrantID: grant.ID, ExpiresAt: now.Add(time.Hour)}
	store.oauthRefreshTokens[refresh.ID] = refresh
	store.oauthRefreshKeys[refresh.Prefix] = refresh.ID
	want("missing refresh rotate", store.RotateOAuthRefreshToken(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{}, commit), credbound.ErrNotFound)
	refresh.UsedAt = &used
	store.oauthRefreshTokens[refresh.ID] = refresh
	want("refresh replay", store.RotateOAuthRefreshToken(ctx, refresh.ID, now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{}, commit), credbound.ErrConflict)
	refresh.UsedAt = nil
	store.oauthRefreshTokens[refresh.ID] = refresh
	want("refresh family mismatch", store.RotateOAuthRefreshToken(ctx, refresh.ID, now, credbound.OAuthAccessToken{}, credbound.OAuthRefreshToken{FamilyID: credbound.MustParseUUID("0198b463-0000-7000-8000-d9298a10d1b0")}, commit), credbound.ErrConflict)
	want("missing access revoke", store.RevokeOAuthAccessToken(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, commit), credbound.ErrNotFound)
	want("missing family revoke", store.RevokeOAuthRefreshFamily(ctx, credbound.MustParseUUID("0198b463-0000-7000-8000-ffa63583dfa6"), now, commit), credbound.ErrNotFound)
}
