package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestOAuthStoreLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	user := credbound.User{ID: f.id(), Email: "root@example.com", DisplayName: "Root", CreatedAt: f.now, UpdatedAt: f.now}
	workspace := credbound.Workspace{ID: f.id(), Name: "Main", CreatedAt: f.now, UpdatedAt: f.now}
	membership := credbound.Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: credbound.RoleAdmin, CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.Bootstrap(ctx, user, f.email(user), credbound.PasswordCredential{UserID: user.ID, Hash: "hash", UpdatedAt: f.now}, workspace, membership, credbound.InstanceAdministrator{UserID: user.ID, Role: credbound.InstanceRoleRoot, CreatedAt: f.now, UpdatedAt: f.now}, f.event(user.ID, "bootstrap", workspace.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	issuer := credbound.OAuthIssuer{ID: f.id(), Issuer: "https://auth.example.com", DCRMode: credbound.OAuthDCROpen, DCROpenRegistrationLimit: 1, CodeTTL: 5 * time.Minute, AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 24 * time.Hour, CreatedAt: f.now, UpdatedAt: f.now}
	issuerCommit := f.event(user.ID, "oauth.issuer.create", issuer.ID, "")
	issuerCommit.Transactional = func(_ context.Context, tx credbound.Tx) error {
		if tx.Kind() != credbound.StoreSQLite {
			t.Fatalf("transaction kind = %s", tx.Kind())
		}
		return nil
	}
	if err := f.store.CreateOAuthIssuer(ctx, issuer, issuerCommit); err != nil {
		t.Fatal(err)
	}
	issuer.UpdatedAt = f.now.Add(time.Minute)
	if err := f.store.UpdateOAuthIssuer(ctx, issuer, f.event(user.ID, "oauth.issuer.update", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthIssuerByID(ctx, issuer.ID); err != nil || !got.UpdatedAt.Equal(issuer.UpdatedAt) {
		t.Fatalf("issuer by id = %#v, %v", got, err)
	}
	if got, err := f.store.OAuthIssuerByURL(ctx, issuer.Issuer); err != nil || got.ID != issuer.ID {
		t.Fatalf("issuer by URL = %#v, %v", got, err)
	}
	rejected := issuer
	rejected.UpdatedAt = rejected.UpdatedAt.Add(time.Minute)
	rejectedCommit := f.event(user.ID, "oauth.issuer.update.rejected", issuer.ID, "")
	rejectedCommit.Transactional = func(context.Context, credbound.Tx) error { return credbound.ErrForbidden }
	if err := f.store.UpdateOAuthIssuer(ctx, rejected, rejectedCommit); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("rejected transaction = %v", err)
	}
	if got, _ := f.store.OAuthIssuerByID(ctx, issuer.ID); !got.UpdatedAt.Equal(issuer.UpdatedAt) {
		t.Fatal("rejected OAuth transaction was committed")
	}
	resource := credbound.OAuthProtectedResource{ID: f.id(), IssuerID: issuer.ID, WorkspaceID: workspace.ID, Resource: "https://mcp.example.com/acme", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthProtectedResource(ctx, resource, f.event(user.ID, "oauth.resource.create", resource.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthProtectedResourceByID(ctx, resource.ID); err != nil || got.Resource != resource.Resource {
		t.Fatalf("resource by id = %#v, %v", got, err)
	}
	if got, err := f.store.OAuthProtectedResourceByURI(ctx, resource.Resource); err != nil || got.ID != resource.ID {
		t.Fatalf("resource by URI = %#v, %v", got, err)
	}
	initial := credbound.OAuthInitialAccessToken{ID: f.id(), IssuerID: issuer.ID, Prefix: "initial", Digest: []byte("digest"), MaxRegistrations: 1, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateOAuthInitialAccessToken(ctx, initial, f.event(user.ID, "oauth.iat.create", initial.ID, "")); err != nil {
		t.Fatal(err)
	}
	client := credbound.OAuthClient{ID: f.id(), IssuerID: issuer.ID, ClientID: "client", Source: credbound.OAuthClientDCR, Name: "Client", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.CreateOAuthClient(ctx, client, initial.ID, f.now, f.event(initial.ID, "oauth.client.create", client.ID, "")); err != nil {
		t.Fatal(err)
	}
	secondDCR := client
	secondDCR.ID, secondDCR.ClientID = f.id(), "second-client"
	if err := f.store.CreateOAuthClient(ctx, secondDCR, "", f.now, f.event("", "oauth.client.create", secondDCR.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("open DCR quota = %v", err)
	}
	if got, err := f.store.OAuthClientByID(ctx, client.ID); err != nil || got.ClientID != client.ClientID {
		t.Fatalf("client by id = %#v, %v", got, err)
	}
	if got, err := f.store.OAuthClientByClientID(ctx, issuer.ID, client.ClientID); err != nil || got.ID != client.ID {
		t.Fatalf("client by client_id = %#v, %v", got, err)
	}
	cimd := client
	cimd.ID, cimd.ClientID, cimd.Source = f.id(), "https://client.example.com/client.json", credbound.OAuthClientCIMD
	if err := f.store.UpsertOAuthCIMDClient(ctx, cimd, f.event("", "oauth.cimd.resolve", cimd.ID, "")); err != nil {
		t.Fatal(err)
	}
	if token, err := f.store.OAuthInitialAccessTokenByPrefix(ctx, initial.Prefix); err != nil || token.RegistrationCount != 1 {
		t.Fatalf("initial token = %#v, %v", token, err)
	}
	if err := f.store.RevokeOAuthInitialAccessToken(ctx, initial.ID, f.now, f.event(user.ID, "oauth.iat.revoke", initial.ID, "")); err != nil {
		t.Fatal(err)
	}
	grant := credbound.OAuthGrant{ID: f.id(), IssuerID: issuer.ID, ClientRecordID: client.ID, UserID: user.ID, WorkspaceID: workspace.ID, ResourceID: resource.ID, Scopes: []string{"documents.read"}, CreatedAt: f.now, UpdatedAt: f.now}
	code := credbound.OAuthAuthorizationCode{ID: f.id(), Prefix: "code", GrantID: grant.ID, ClientRecordID: client.ID, ResourceID: resource.ID, ExpiresAt: f.now.Add(time.Minute), CreatedAt: f.now}
	if err := f.store.CreateOAuthGrantAndCode(ctx, grant, code, f.event(user.ID, "oauth.authorization", grant.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, err := f.store.OAuthGrant(ctx, grant.ID); err != nil || got.UserID != user.ID {
		t.Fatalf("grant = %#v, %v", got, err)
	}
	if got, err := f.store.OAuthAuthorizationCodeByPrefix(ctx, code.Prefix); err != nil || got.ID != code.ID {
		t.Fatalf("code = %#v, %v", got, err)
	}
	access := credbound.OAuthAccessToken{ID: f.id(), Prefix: "access", GrantID: grant.ID, ClientRecordID: client.ID, UserID: user.ID, WorkspaceID: workspace.ID, ResourceID: resource.ID, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Minute)}
	refresh := credbound.OAuthRefreshToken{ID: f.id(), FamilyID: f.id(), Prefix: "refresh", GrantID: grant.ID, ClientRecordID: client.ID, UserID: user.ID, WorkspaceID: workspace.ID, ResourceID: resource.ID, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.ConsumeOAuthAuthorizationCode(ctx, code.ID, f.now, access, &refresh, f.event(client.ID, "oauth.token.issue", access.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConsumeOAuthAuthorizationCode(ctx, code.ID, f.now, access, &refresh, f.event(client.ID, "oauth.token.replay", access.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("code replay = %v", err)
	}
	if _, err := f.store.OAuthAccessTokenByPrefix(ctx, access.Prefix); err != nil {
		t.Fatal(err)
	}
	replacement := refresh
	replacement.ID, replacement.Prefix, replacement.UsedAt = f.id(), "refresh2", nil
	access2 := access
	access2.ID, access2.Prefix = f.id(), "access2"
	mismatched := replacement
	mismatched.ID, mismatched.FamilyID, mismatched.Prefix = f.id(), f.id(), "refresh-mismatched"
	if err := f.store.RotateOAuthRefreshToken(ctx, refresh.ID, f.now, access2, mismatched, f.event(client.ID, "oauth.token.refresh", access2.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("refresh family mismatch = %v", err)
	}
	if err := f.store.RotateOAuthRefreshToken(ctx, refresh.ID, f.now, access2, replacement, f.event(client.ID, "oauth.token.refresh", access2.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RotateOAuthRefreshToken(ctx, refresh.ID, f.now, access2, replacement, f.event(client.ID, "oauth.token.replay", access2.ID, workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("refresh replay = %v", err)
	}
	if err := f.store.RevokeOAuthAccessToken(ctx, access2.ID, f.now, f.event(client.ID, "oauth.token.revoke", access2.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if revoked, err := f.store.OAuthAccessTokenByPrefix(ctx, access2.Prefix); err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoked access = %#v, %v", revoked, err)
	}
	if previous, err := f.store.OAuthRefreshTokenByPrefix(ctx, refresh.Prefix); err != nil || previous.UsedAt == nil {
		t.Fatalf("rotated token = %#v, %v", previous, err)
	}
	if err := f.store.RevokeOAuthRefreshFamily(ctx, refresh.FamilyID, f.now, f.event(client.ID, "oauth.token.revoke", refresh.FamilyID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeOAuthRefreshFamily(ctx, refresh.FamilyID, f.now, f.event(client.ID, "oauth.token.revoke_again", refresh.FamilyID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if current, err := f.store.OAuthRefreshTokenByPrefix(ctx, replacement.Prefix); err != nil || current.RevokedAt == nil {
		t.Fatalf("revoked family = %#v, %v", current, err)
	}
	page := credbound.PageRequest{Limit: 50}
	if values := collectOAuthPage(t, f.store.OAuthIssuers(ctx, page)); len(values) != 1 {
		t.Fatalf("issuer list = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.OAuthProtectedResources(ctx, workspace.ID, page)); len(values) != 1 {
		t.Fatalf("resource list = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.OAuthClients(ctx, issuer.ID, page)); len(values) != 2 || values[0].SecretDigest != nil {
		t.Fatalf("client list = %#v", values)
	}
	if values := collectOAuthPage(t, f.store.OAuthGrants(ctx, user.ID, workspace.ID, page)); len(values) != 1 {
		t.Fatalf("grant list = %#v", values)
	}
	activeGrant := grant
	activeGrant.ID, activeGrant.CreatedAt, activeGrant.UpdatedAt = f.id(), f.now, f.now
	activeCode := code
	activeCode.ID, activeCode.Prefix, activeCode.GrantID, activeCode.CreatedAt = f.id(), "active-code", activeGrant.ID, f.now
	if err := f.store.CreateOAuthGrantAndCode(ctx, activeGrant, activeCode, f.event(user.ID, "oauth.authorization.active", activeGrant.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	activeAccess := access
	activeAccess.ID, activeAccess.Prefix, activeAccess.GrantID = f.id(), "active-access", activeGrant.ID
	activeRefresh := refresh
	activeRefresh.ID, activeRefresh.FamilyID, activeRefresh.Prefix, activeRefresh.GrantID = f.id(), f.id(), "active-refresh", activeGrant.ID
	if err := f.store.ConsumeOAuthAuthorizationCode(ctx, activeCode.ID, f.now, activeAccess, &activeRefresh, f.event(client.ID, "oauth.token.active", activeAccess.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RevokeOAuthGrant(ctx, activeGrant.ID, f.now, f.event(user.ID, "oauth.grant.active.revoke", activeGrant.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.store.OAuthAccessTokenByPrefix(ctx, activeAccess.Prefix); got.RevokedAt == nil {
		t.Fatal("grant revocation did not revoke access token")
	}
	if got, _ := f.store.OAuthRefreshTokenByPrefix(ctx, activeRefresh.Prefix); got.RevokedAt == nil {
		t.Fatal("grant revocation did not revoke refresh token")
	}
	if err := f.store.RevokeOAuthGrant(ctx, grant.ID, f.now, f.event(user.ID, "oauth.grant.revoke", grant.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthClientDisabled(ctx, client.ID, true, f.now, f.event(user.ID, "oauth.client.disable", client.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthClientDisabled(ctx, client.ID, false, f.now, f.event(user.ID, "oauth.client.enable", client.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthProtectedResourceDisabled(ctx, resource.ID, true, f.now, f.event(user.ID, "oauth.resource.disable", resource.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthProtectedResourceDisabled(ctx, resource.ID, false, f.now, f.event(user.ID, "oauth.resource.enable", resource.ID, workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthIssuerDisabled(ctx, issuer.ID, true, f.now, f.event(user.ID, "oauth.issuer.disable", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetOAuthIssuerDisabled(ctx, issuer.ID, false, f.now, f.event(user.ID, "oauth.issuer.enable", issuer.ID, "")); err != nil {
		t.Fatal(err)
	}
}

func collectOAuthPage[T any](t *testing.T, sequence func(func(credbound.PageEvent[T], error) bool)) []T {
	t.Helper()
	var values []T
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			values = append(values, *event.Data)
		}
	}
	return values
}

func TestOAuthStoreMissingRecords(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	wantNotFound := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, credbound.ErrNotFound) {
			t.Fatalf("%s = %v", name, err)
		}
	}
	_, err := f.store.OAuthIssuerByID(ctx, "0198b463-0000-7000-8000-000000000001")
	wantNotFound("issuer id", err)
	_, err = f.store.OAuthIssuerByURL(ctx, "https://missing.example.com")
	wantNotFound("issuer URL", err)
	_, err = f.store.OAuthProtectedResourceByID(ctx, "0198b463-0000-7000-8000-000000000001")
	wantNotFound("resource id", err)
	_, err = f.store.OAuthProtectedResourceByURI(ctx, "https://missing.example.com")
	wantNotFound("resource URI", err)
	_, err = f.store.OAuthClientByID(ctx, "0198b463-0000-7000-8000-000000000001")
	wantNotFound("client id", err)
	_, err = f.store.OAuthClientByClientID(ctx, "0198b463-0000-7000-8000-000000000001", "missing")
	wantNotFound("client key", err)
	_, err = f.store.OAuthInitialAccessTokenByPrefix(ctx, "missing")
	wantNotFound("initial", err)
	_, err = f.store.OAuthGrant(ctx, "0198b463-0000-7000-8000-000000000001")
	wantNotFound("grant", err)
	_, err = f.store.OAuthAuthorizationCodeByPrefix(ctx, "missing")
	wantNotFound("code", err)
	_, err = f.store.OAuthAccessTokenByPrefix(ctx, "missing")
	wantNotFound("access", err)
	_, err = f.store.OAuthRefreshTokenByPrefix(ctx, "missing")
	wantNotFound("refresh", err)
	missingID := "0198b463-0000-7000-8000-000000000001"
	wantNotFound("issuer update", f.store.UpdateOAuthIssuer(ctx, credbound.OAuthIssuer{ID: missingID, Issuer: "https://missing.example.com"}, f.event("", "oauth.issuer.update", missingID, "")))
	wantNotFound("initial revoke", f.store.RevokeOAuthInitialAccessToken(ctx, missingID, f.now, f.event("", "oauth.initial.revoke", missingID, "")))
	wantNotFound("access revoke", f.store.RevokeOAuthAccessToken(ctx, missingID, f.now, f.event("", "oauth.access.revoke", missingID, "")))
	wantNotFound("family revoke", f.store.RevokeOAuthRefreshFamily(ctx, missingID, f.now, f.event("", "oauth.family.revoke", missingID, "")))
}

func TestOAuthStoreStreamPaginationAndFailures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for index := range 2 {
		issuer := credbound.OAuthIssuer{ID: f.id(), Issuer: fmt.Sprintf("https://auth-%d.example.com", index), CreatedAt: f.now, UpdatedAt: f.now}
		if err := f.store.CreateOAuthIssuer(ctx, issuer, f.event("", "oauth.issuer.create", issuer.ID, "")); err != nil {
			t.Fatal(err)
		}
	}
	items, hasMore := 0, false
	for event, err := range f.store.OAuthIssuers(ctx, credbound.PageRequest{Limit: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			items++
		}
		if event.End != nil {
			hasMore = event.End.HasMore && event.End.NextCursor != ""
		}
	}
	if items != 1 || !hasMore {
		t.Fatalf("page = %d, hasMore=%v", items, hasMore)
	}
	if err := firstOAuthPageError(f.store.OAuthIssuers(ctx, credbound.PageRequest{Cursor: "%%%", Limit: 50})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid cursor = %v", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := firstOAuthPageError(f.store.OAuthIssuers(canceled, credbound.PageRequest{Limit: 50})); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream = %v", err)
	}
	if _, err := f.db.Exec(`INSERT INTO credbound_oauth_issuers (id, issuer, created_at, data_json) VALUES (?, ?, ?, '{')`, f.id(), "https://corrupt.example.com", f.now); err != nil {
		t.Fatal(err)
	}
	if err := firstOAuthPageError(f.store.OAuthIssuers(ctx, credbound.PageRequest{Limit: 50})); err == nil {
		t.Fatal("corrupt OAuth JSON was accepted")
	}
}

func firstOAuthPageError[T any](sequence func(func(credbound.PageEvent[T], error) bool)) error {
	for _, err := range sequence {
		if err != nil {
			return err
		}
	}
	return nil
}
