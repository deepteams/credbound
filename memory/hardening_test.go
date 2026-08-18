package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func TestHardeningCanceledOperations(t *testing.T) {
	f := newStoreFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	event := f.event("canceled")
	reset := credbound.PasswordResetCredential{ID: f.id(), UserID: f.user.ID}
	link := credbound.EmailAuthenticationCredential{ID: f.id(), UserID: f.user.ID}
	invitation := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: f.workspace.ID, Email: "x@example.com", Role: credbound.RoleMember}
	membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID}

	checks := []error{
		f.store.RevokeUserCredentials(ctx, f.user.ID, f.now, event),
		f.store.CreatePasswordReset(ctx, reset, event),
		f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: f.user.ID}, f.now, event),
		f.store.CreateEmailAuthentication(ctx, link, event),
		f.store.ConsumeEmailAuthentication(ctx, link.ID, f.user.ID, f.now, event),
		f.store.CreateWorkspaceInvitation(ctx, invitation, event),
		f.store.AcceptWorkspaceInvitation(ctx, invitation.ID, f.user.ID, f.now, membership, event),
		f.store.RegisterInvitedUser(ctx, invitation.ID, f.user, f.email(f.user), credbound.PasswordCredential{UserID: f.user.ID}, membership, f.now, event),
		f.store.RevokeWorkspaceInvitation(ctx, f.workspace.ID, invitation.ID, f.now, event),
	}
	for index, err := range checks {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled mutation %d = %v", index, err)
		}
	}
	if _, err := f.store.PasswordResetByID(ctx, reset.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled reset lookup = %v", err)
	}
	if _, err := f.store.EmailAuthenticationByID(ctx, link.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled link lookup = %v", err)
	}
	if _, err := f.store.LoginThrottleByUserID(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled throttle lookup = %v", err)
	}
	if _, err := f.store.RecordLoginFailure(ctx, f.user.ID, f.now, 3, f.now, event); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled login failure = %v", err)
	}
	if _, err := f.store.CountUnusedRecoveryCodes(ctx, f.user.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recovery count = %v", err)
	}
	if _, err := f.store.WorkspaceInvitationByID(ctx, invitation.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled invitation lookup = %v", err)
	}
	if _, err := f.store.PendingWorkspaceInvitation(ctx, f.workspace.ID, "x@example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled pending lookup = %v", err)
	}
	if _, _, err := f.store.AuditChainHead(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled chain head = %v", err)
	}
	for _, err := range f.store.ChainedAuditEvents(ctx, 0) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled chained events = %v", err)
		}
	}
	for _, err := range f.store.WorkspaceInvitations(ctx, f.workspace.ID, credbound.PageRequest{Limit: 10}) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled invitations list = %v", err)
		}
	}
	for _, err := range f.store.Passkeys(ctx, f.user.ID) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled passkeys = %v", err)
		}
	}
	for _, err := range f.store.SSOIdentities(ctx, f.user.ID, credbound.PageRequest{Limit: 10}) {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled SSO identities = %v", err)
		}
	}
}

func TestHardeningEarlyBreaks(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	for index := range 2 {
		passkey := credbound.Passkey{ID: f.id(), UserID: f.user.ID, Name: "k", CredentialID: []byte{byte(index)}, CredentialJSON: []byte("sealed"), CreatedAt: f.now}
		if err := f.store.SavePasskey(ctx, passkey, f.event("passkey")); err != nil {
			t.Fatal(err)
		}
		identity := credbound.SSOIdentity{ID: f.id(), UserID: f.user.ID, ProviderConfigurationID: f.id(), ProviderKind: credbound.SSOProviderOIDC, Issuer: "https://idp", Subject: f.id(), Email: f.user.Email, CreatedAt: f.now}
		if err := f.store.LinkSSO(ctx, identity, f.event("sso")); err != nil {
			t.Fatal(err)
		}
		invitation := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: f.workspace.ID, Email: []string{"a", "b"}[index] + "@example.com", Role: credbound.RoleMember, InvitedBy: f.user.ID, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
		if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event("invite")); err != nil {
			t.Fatal(err)
		}
	}
	for range f.store.Passkeys(ctx, f.user.ID) {
		break
	}
	for range f.store.SSOIdentities(ctx, f.user.ID, credbound.PageRequest{Limit: 10}) {
		break
	}
	for range f.store.WorkspaceInvitations(ctx, f.workspace.ID, credbound.PageRequest{Limit: 1}) {
		break
	}
	for range f.store.ChainedAuditEvents(ctx, 0) {
		break
	}
	// Cursor-driven second page of the invitation listing.
	var cursor string
	for event, err := range f.store.WorkspaceInvitations(ctx, f.workspace.ID, credbound.PageRequest{Limit: 1}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.End != nil && event.End.HasMore {
			cursor = event.End.NextCursor
		}
	}
	if cursor == "" {
		t.Fatal("missing pagination cursor")
	}
	for _, err := range f.store.WorkspaceInvitations(ctx, f.workspace.ID, credbound.PageRequest{Limit: 1, Cursor: cursor}) {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, err := range f.store.WorkspaceInvitations(ctx, f.workspace.ID, credbound.PageRequest{Limit: 1, Cursor: "!!!"}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("bad cursor error = %v", err)
		}
	}
}

func TestHardeningNotFoundAndConflictBranches(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	unknown := f.id()

	if err := f.store.RevokeUserCredentials(ctx, unknown, f.now, f.event("revoke")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("revoke unknown user = %v", err)
	}
	if err := f.store.CreatePasswordReset(ctx, credbound.PasswordResetCredential{ID: f.id(), UserID: unknown}, f.event("reset")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("reset for unknown user = %v", err)
	}
	reset := credbound.PasswordResetCredential{ID: f.id(), UserID: f.user.ID, Digest: []byte("d"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreatePasswordReset(ctx, reset, f.event("reset")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreatePasswordReset(ctx, reset, f.event("reset")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate reset = %v", err)
	}
	if err := f.store.CompletePasswordReset(ctx, unknown, credbound.PasswordCredential{UserID: f.user.ID}, f.now, f.event("complete")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("complete unknown reset = %v", err)
	}
	if err := f.store.CompletePasswordReset(ctx, reset.ID, credbound.PasswordCredential{UserID: unknown}, f.now, f.event("complete")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("complete for unknown user = %v", err)
	}

	if err := f.store.CreateEmailAuthentication(ctx, credbound.EmailAuthenticationCredential{ID: f.id(), UserID: unknown}, f.event("link")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("link for unknown user = %v", err)
	}
	link := credbound.EmailAuthenticationCredential{ID: f.id(), UserID: f.user.ID, Digest: []byte("m"), CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateEmailAuthentication(ctx, link, f.event("link")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateEmailAuthentication(ctx, link, f.event("link")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate link = %v", err)
	}
	if err := f.store.ConsumeEmailAuthentication(ctx, link.ID, unknown, f.now, f.event("consume")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("consume with wrong user = %v", err)
	}

	if err := f.store.CreateWorkspaceInvitation(ctx, credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: unknown, Email: "a@example.com"}, f.event("invite")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("invitation for unknown workspace = %v", err)
	}
	invitation := credbound.WorkspaceInvitation{ID: f.id(), WorkspaceID: f.workspace.ID, Email: "a@example.com", Role: credbound.RoleMember, InvitedBy: f.user.ID, CreatedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event("invite")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateWorkspaceInvitation(ctx, invitation, f.event("invite")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate invitation id = %v", err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, unknown, f.user.ID, f.now, credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID}, f.event("accept")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("accept unknown invitation = %v", err)
	}
	if err := f.store.AcceptWorkspaceInvitation(ctx, invitation.ID, unknown, f.now, credbound.Membership{WorkspaceID: f.workspace.ID, UserID: unknown}, f.event("accept")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("accept with unknown user = %v", err)
	}
	existing := credbound.User{ID: f.id(), Email: "existing@example.com", DisplayName: "Existing", CreatedAt: f.now, UpdatedAt: f.now}
	if err := f.store.RegisterInvitedUser(ctx, unknown, existing, f.email(existing), credbound.PasswordCredential{UserID: existing.ID}, credbound.Membership{WorkspaceID: f.workspace.ID, UserID: existing.ID}, f.now, f.event("register")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("register on unknown invitation = %v", err)
	}
	if err := f.store.RegisterInvitedUser(ctx, invitation.ID, f.user, f.email(f.user), credbound.PasswordCredential{UserID: f.user.ID}, credbound.Membership{WorkspaceID: f.workspace.ID, UserID: f.user.ID}, f.now, f.event("register")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("register with existing user = %v", err)
	}
	if err := f.store.RevokeWorkspaceInvitation(ctx, unknown, invitation.ID, f.now, f.event("revoke")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("revoke with wrong workspace = %v", err)
	}
}
