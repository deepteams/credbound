package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func (f *fixture) newWorkspaceDomain(t *testing.T, workspaceID, name string) credbound.WorkspaceDomain {
	t.Helper()
	domain := credbound.WorkspaceDomain{
		ID: f.id(), WorkspaceID: workspaceID, Domain: name,
		Challenge: "credbound-domain-verification=value",
		CreatedAt: f.now, UpdatedAt: f.now,
	}
	f.now = f.now.Add(time.Millisecond)
	if err := f.store.CreateWorkspaceDomain(context.Background(), domain, f.event(domain.WorkspaceID, "domain.create", domain.ID, workspaceID)); err != nil {
		t.Fatal(err)
	}
	return domain
}

func TestWorkspaceDomainStoreLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	domain := f.newWorkspaceDomain(t, users.workspace.ID, "corp.example.com")

	if err := f.store.CreateWorkspaceDomain(ctx, domain, f.event(users.root.ID, "domain.duplicate", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate domain error = %v", err)
	}
	sameName := domain
	sameName.ID = f.id()
	if err := f.store.CreateWorkspaceDomain(ctx, sameName, f.event(users.root.ID, "domain.duplicate_name", sameName.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate name error = %v", err)
	}
	orphan := domain
	orphan.ID, orphan.WorkspaceID, orphan.Domain = f.id(), f.id(), "orphan.example.com"
	if err := f.store.CreateWorkspaceDomain(ctx, orphan, f.event(users.root.ID, "domain.orphan", orphan.ID, "")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("orphan workspace error = %v", err)
	}

	stored, err := f.store.WorkspaceDomainByID(ctx, domain.ID)
	if err != nil || stored.Domain != "corp.example.com" || stored.Challenge != domain.Challenge ||
		stored.ConfirmedAt != nil || stored.AutoJoin || stored.EnforceSSO || stored.WorkspaceID != users.workspace.ID {
		t.Fatalf("stored domain = %#v, %v", stored, err)
	}
	if _, err := f.store.WorkspaceDomainByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown lookup error = %v", err)
	}
	if _, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unconfirmed hot lookup error = %v", err)
	}

	policy := credbound.WorkspaceDomainPolicyInput{AutoJoin: true, AutoJoinRole: credbound.RoleMember, SSOProviderConfigurationID: "0198b463-0000-7000-8000-0000000000aa", EnforceSSO: true}
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, domain.ID, policy, f.now, f.event(users.root.ID, "domain.policy_pending", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("pending policy error = %v", err)
	}
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, f.id(), policy, f.now, f.event(users.root.ID, "domain.policy_unknown", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown policy error = %v", err)
	}

	confirmedAt := f.now.Add(time.Hour).UTC()
	if err := f.store.ConfirmWorkspaceDomain(ctx, domain.ID, confirmedAt, f.event(users.root.ID, "domain.confirm", domain.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConfirmWorkspaceDomain(ctx, domain.ID, confirmedAt.Add(time.Hour), f.event(users.root.ID, "domain.confirm_repeat", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("double confirm error = %v", err)
	}
	if err := f.store.ConfirmWorkspaceDomain(ctx, f.id(), confirmedAt, f.event(users.root.ID, "domain.confirm_unknown", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown confirm error = %v", err)
	}
	confirmed, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com")
	if err != nil || confirmed.ConfirmedAt == nil || !confirmed.ConfirmedAt.Equal(confirmedAt) || !confirmed.UpdatedAt.Equal(confirmedAt) {
		t.Fatalf("confirmed domain = %#v, %v", confirmed, err)
	}

	updatedAt := confirmedAt.Add(time.Minute)
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, domain.ID, policy, updatedAt, f.event(users.root.ID, "domain.policy", domain.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	updated, err := f.store.WorkspaceDomainByID(ctx, domain.ID)
	if err != nil || !updated.AutoJoin || updated.AutoJoinRole != credbound.RoleMember ||
		updated.SSOProviderConfigurationID != policy.SSOProviderConfigurationID || !updated.EnforceSSO || !updated.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated domain = %#v, %v", updated, err)
	}

	if err := f.store.DeleteWorkspaceDomain(ctx, domain.ID, f.event(users.root.ID, "domain.delete", domain.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteWorkspaceDomain(ctx, domain.ID, f.event(users.root.ID, "domain.delete_repeat", domain.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("double delete error = %v", err)
	}
	if _, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("deleted hot lookup error = %v", err)
	}
	// The name becomes free again.
	f.newWorkspaceDomain(t, users.workspace.ID, "corp.example.com")
}

func TestWorkspaceDomainStorePagination(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	var ids []string
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		ids = append(ids, f.newWorkspaceDomain(t, users.workspace.ID, name).ID)
	}
	var first []credbound.WorkspaceDomain
	var end credbound.PageEnd
	for event, err := range f.store.WorkspaceDomains(ctx, users.workspace.ID, credbound.PageRequest{Limit: 2}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			first = append(first, *event.Data)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	if len(first) != 2 || !end.HasMore || end.NextCursor == "" || first[0].ID != ids[2] || first[1].ID != ids[1] {
		t.Fatalf("first page = %#v, %#v", first, end)
	}
	var rest []credbound.WorkspaceDomain
	for event, err := range f.store.WorkspaceDomains(ctx, users.workspace.ID, credbound.PageRequest{Limit: 2, Cursor: end.NextCursor}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			rest = append(rest, *event.Data)
		}
	}
	if len(rest) != 1 || rest[0].ID != ids[0] {
		t.Fatalf("second page = %#v", rest)
	}
	for _, err := range f.store.WorkspaceDomains(ctx, users.workspace.ID, credbound.PageRequest{Limit: 2, Cursor: "%%%"}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid cursor error = %v", err)
		}
		break
	}
	// A consumer may stop mid-stream.
	for event, err := range f.store.WorkspaceDomains(ctx, users.workspace.ID, credbound.PageRequest{Limit: 3}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			break
		}
	}
}

func TestWorkspaceDomainStoreJITProvision(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	users := f.bootstrapSessionUsers(t)
	newAccount := func(address, subject string) (credbound.User, credbound.EmailAddress, credbound.Membership, credbound.SSOIdentity) {
		now := f.now
		user := credbound.User{ID: f.id(), Email: address, DisplayName: address, LastSeenAt: &now, CreatedAt: now, UpdatedAt: now}
		email := credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: address, Primary: true, VerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
		membership := credbound.Membership{WorkspaceID: users.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: "jit:domain", CreatedAt: now, UpdatedAt: now}
		identity := credbound.SSOIdentity{
			ID: f.id(), UserID: user.ID, ProviderConfigurationID: "0198b463-0000-7000-8000-0000000000aa",
			ProviderKind: credbound.SSOProviderOIDC, Issuer: "https://idp.example.com", Subject: subject,
			Email: address, CreatedAt: now, LastUsedAt: &now,
		}
		f.now = f.now.Add(time.Millisecond)
		return user, email, membership, identity
	}

	user, email, membership, identity := newAccount("alice@corp.example.com", "subject-1")
	if err := f.store.JITProvisionSSOUser(ctx, user, email, membership, identity, f.now, f.event(user.ID, "jit.provision", user.ID, users.workspace.ID)); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.UserByEmail(ctx, "alice@corp.example.com")
	if err != nil || stored.ID != user.ID {
		t.Fatalf("JIT user = %#v, %v", stored, err)
	}
	if _, err := f.store.PasswordByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("JIT user has a password: %v", err)
	}
	storedMembership, err := f.store.Membership(ctx, users.workspace.ID, user.ID)
	if err != nil || storedMembership.ProvisioningSource != "jit:domain" || storedMembership.Role != credbound.RoleMember {
		t.Fatalf("JIT membership = %#v, %v", storedMembership, err)
	}
	linked, err := f.store.SSOIdentity(ctx, identity.ProviderConfigurationID, identity.Issuer, identity.Subject)
	if err != nil || linked.UserID != user.ID {
		t.Fatalf("JIT identity = %#v, %v", linked, err)
	}

	duplicateEmail, email2, membership2, identity2 := newAccount("alice@corp.example.com", "subject-2")
	if err := f.store.JITProvisionSSOUser(ctx, duplicateEmail, email2, membership2, identity2, f.now, f.event(duplicateEmail.ID, "jit.duplicate_email", duplicateEmail.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate email error = %v", err)
	}
	duplicateIdentity, email3, membership3, identity3 := newAccount("bob@corp.example.com", "subject-1")
	if err := f.store.JITProvisionSSOUser(ctx, duplicateIdentity, email3, membership3, identity3, f.now, f.event(duplicateIdentity.ID, "jit.duplicate_identity", duplicateIdentity.ID, users.workspace.ID)); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate identity error = %v", err)
	}

	orphanUser, email5, membership5, identity5 := newAccount("carol@corp.example.com", "subject-3")
	membership5.WorkspaceID = f.id()
	if err := f.store.JITProvisionSSOUser(ctx, orphanUser, email5, membership5, identity5, f.now, f.event(orphanUser.ID, "jit.orphan", orphanUser.ID, "")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("orphan workspace error = %v", err)
	}

	// A failing transaction hook rolls the whole provision back atomically.
	rollbackUser, email4, membership4, identity4 := newAccount("dave@corp.example.com", "subject-4")
	commit := f.event(rollbackUser.ID, "jit.rollback", rollbackUser.ID, users.workspace.ID)
	boom := errors.New("host write rejected")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	if err := f.store.JITProvisionSSOUser(ctx, rollbackUser, email4, membership4, identity4, f.now, commit); !errors.Is(err, boom) {
		t.Fatalf("hook rollback error = %v", err)
	}
	if _, err := f.store.UserByEmail(ctx, "dave@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rolled-back user survived: %v", err)
	}
	if _, err := f.store.SSOIdentity(ctx, identity4.ProviderConfigurationID, identity4.Issuer, identity4.Subject); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rolled-back identity survived: %v", err)
	}
}
