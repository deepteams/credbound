package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

func (f *storeFixture) domain(name string) credbound.WorkspaceDomain {
	domain := credbound.WorkspaceDomain{
		ID: f.id(), WorkspaceID: f.workspace.ID, Domain: name,
		Challenge: "credbound-domain-verification=value",
		CreatedAt: f.now, UpdatedAt: f.now,
	}
	f.now = f.now.Add(time.Millisecond)
	return domain
}

func TestWorkspaceDomainStoreLifecycle(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	domain := f.domain("corp.example.com")
	if err := f.store.CreateWorkspaceDomain(ctx, domain, time.Time{}, f.event("domain.create")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateWorkspaceDomain(ctx, domain, time.Time{}, f.event("domain.create.duplicate")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate id error = %v", err)
	}
	sameName := f.domain("corp.example.com")
	if err := f.store.CreateWorkspaceDomain(ctx, sameName, time.Time{}, f.event("domain.create.name")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate name error = %v", err)
	}
	orphan := f.domain("orphan.example.com")
	orphan.WorkspaceID = f.id()
	if err := f.store.CreateWorkspaceDomain(ctx, orphan, time.Time{}, f.event("domain.create.orphan")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("orphan workspace error = %v", err)
	}

	stored, err := f.store.WorkspaceDomainByID(ctx, domain.ID)
	if err != nil || stored.Domain != "corp.example.com" || stored.Challenge != domain.Challenge || stored.ConfirmedAt != nil {
		t.Fatalf("stored domain = %#v, %v", stored, err)
	}
	if _, err := f.store.WorkspaceDomainByID(ctx, f.id()); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown lookup error = %v", err)
	}
	// The unconfirmed record is invisible to the hot enforcement lookup.
	if _, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unconfirmed hot lookup error = %v", err)
	}

	policy := credbound.WorkspaceDomainPolicyInput{AutoJoin: true, AutoJoinRole: credbound.RoleMember, SSOProviderConfigurationID: f.id(), EnforceSSO: true}
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, domain.ID, policy, f.now, f.event("domain.policy.pending")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("pending policy error = %v", err)
	}

	confirmedAt := f.now.Add(time.Hour)
	if err := f.store.ConfirmWorkspaceDomain(ctx, domain.ID, confirmedAt, f.event("domain.confirm")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ConfirmWorkspaceDomain(ctx, domain.ID, confirmedAt.Add(time.Hour), f.event("domain.confirm.repeat")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("double confirm error = %v", err)
	}
	if err := f.store.ConfirmWorkspaceDomain(ctx, f.id(), confirmedAt, f.event("domain.confirm.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown confirm error = %v", err)
	}
	confirmed, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com")
	if err != nil || confirmed.ConfirmedAt == nil || !confirmed.ConfirmedAt.Equal(confirmedAt) || !confirmed.UpdatedAt.Equal(confirmedAt) {
		t.Fatalf("confirmed domain = %#v, %v", confirmed, err)
	}
	// The returned value is a clone: mutating it does not corrupt the store.
	*confirmed.ConfirmedAt = confirmedAt.Add(time.Hour)
	again, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com")
	if err != nil || !again.ConfirmedAt.Equal(confirmedAt) {
		t.Fatalf("confirmed timestamp aliased: %#v, %v", again, err)
	}
	if _, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "ghost.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown hot lookup error = %v", err)
	}

	updatedAt := confirmedAt.Add(time.Minute)
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, domain.ID, policy, updatedAt, f.event("domain.policy")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.UpdateWorkspaceDomainPolicy(ctx, f.id(), policy, updatedAt, f.event("domain.policy.unknown")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown policy error = %v", err)
	}
	updated, err := f.store.WorkspaceDomainByID(ctx, domain.ID)
	if err != nil || !updated.AutoJoin || updated.AutoJoinRole != credbound.RoleMember ||
		updated.SSOProviderConfigurationID != policy.SSOProviderConfigurationID || !updated.EnforceSSO || !updated.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("updated domain = %#v, %v", updated, err)
	}

	if err := f.store.DeleteWorkspaceDomain(ctx, domain.ID, f.event("domain.delete")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteWorkspaceDomain(ctx, domain.ID, f.event("domain.delete.repeat")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("double delete error = %v", err)
	}
	if _, err := f.store.ConfirmedWorkspaceDomainByName(ctx, "corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("deleted hot lookup error = %v", err)
	}
	// The name becomes free again.
	if err := f.store.CreateWorkspaceDomain(ctx, f.domain("corp.example.com"), time.Time{}, f.event("domain.recreate")); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceDomainStorePagination(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	var ids []string
	for _, name := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		domain := f.domain(name)
		if err := f.store.CreateWorkspaceDomain(ctx, domain, time.Time{}, f.event("domain.create."+name)); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, domain.ID)
	}
	var first []credbound.WorkspaceDomain
	var end credbound.PageEnd
	for event, err := range f.store.WorkspaceDomains(ctx, f.workspace.ID, credbound.PageRequest{Limit: 2}) {
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
	for event, err := range f.store.WorkspaceDomains(ctx, f.workspace.ID, credbound.PageRequest{Limit: 2, Cursor: end.NextCursor}) {
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
	for _, err := range f.store.WorkspaceDomains(ctx, f.workspace.ID, credbound.PageRequest{Limit: 2, Cursor: "%%%"}) {
		if !errors.Is(err, credbound.ErrInvalidInput) {
			t.Fatalf("invalid cursor error = %v", err)
		}
		break
	}
}

func TestWorkspaceDomainStoreJITProvision(t *testing.T) {
	f := newStoreFixture(t)
	ctx := context.Background()
	newAccount := func(address, subject string) (credbound.User, credbound.EmailAddress, credbound.Membership, credbound.SSOIdentity) {
		user := credbound.User{ID: f.id(), Email: address, DisplayName: address, LastSeenAt: &f.now, CreatedAt: f.now, UpdatedAt: f.now}
		email := credbound.EmailAddress{ID: f.id(), UserID: user.ID, Address: address, Primary: true, VerifiedAt: &f.now, CreatedAt: f.now, UpdatedAt: f.now}
		membership := credbound.Membership{WorkspaceID: f.workspace.ID, UserID: user.ID, Role: credbound.RoleMember, Status: credbound.MembershipActive, ProvisioningSource: "jit:domain", CreatedAt: f.now, UpdatedAt: f.now}
		identity := credbound.SSOIdentity{
			ID: f.id(), UserID: user.ID, ProviderConfigurationID: "0198b463-0000-7000-8000-0000000000aa",
			ProviderKind: credbound.SSOProviderOIDC, Issuer: "https://idp.example.com", Subject: subject,
			Email: address, CreatedAt: f.now, LastUsedAt: &f.now,
		}
		return user, email, membership, identity
	}

	user, email, membership, identity := newAccount("alice@corp.example.com", "subject-1")
	if err := f.store.JITProvisionSSOUser(ctx, user, email, membership, identity, f.now, f.event("jit.provision")); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.UserByEmail(ctx, "alice@corp.example.com")
	if err != nil || stored.ID != user.ID {
		t.Fatalf("JIT user = %#v, %v", stored, err)
	}
	if _, err := f.store.PasswordByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("JIT user has a password: %v", err)
	}
	storedMembership, err := f.store.Membership(ctx, f.workspace.ID, user.ID)
	if err != nil || storedMembership.ProvisioningSource != "jit:domain" {
		t.Fatalf("JIT membership = %#v, %v", storedMembership, err)
	}
	linked, err := f.store.SSOIdentity(ctx, identity.ProviderConfigurationID, identity.Issuer, identity.Subject)
	if err != nil || linked.UserID != user.ID {
		t.Fatalf("JIT identity = %#v, %v", linked, err)
	}

	// A taken address, user, or identity fails with ErrConflict.
	duplicateEmail, email2, membership2, identity2 := newAccount("alice@corp.example.com", "subject-2")
	if err := f.store.JITProvisionSSOUser(ctx, duplicateEmail, email2, membership2, identity2, f.now, f.event("jit.duplicate.email")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate email error = %v", err)
	}
	duplicateIdentity, email3, membership3, identity3 := newAccount("bob@corp.example.com", "subject-1")
	if err := f.store.JITProvisionSSOUser(ctx, duplicateIdentity, email3, membership3, identity3, f.now, f.event("jit.duplicate.identity")); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate identity error = %v", err)
	}
	orphanUser, email4, membership4, identity4 := newAccount("carol@corp.example.com", "subject-3")
	membership4.WorkspaceID = f.id()
	if err := f.store.JITProvisionSSOUser(ctx, orphanUser, email4, membership4, identity4, f.now, f.event("jit.orphan")); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("orphan workspace error = %v", err)
	}

	// A failing transaction hook rolls the whole provision back atomically.
	rollbackUser, email5, membership5, identity5 := newAccount("dave@corp.example.com", "subject-4")
	commit := f.event("jit.rollback")
	boom := errors.New("host write rejected")
	commit.Transactional = func(context.Context, credbound.Tx) error { return boom }
	if err := f.store.JITProvisionSSOUser(ctx, rollbackUser, email5, membership5, identity5, f.now, commit); !errors.Is(err, boom) {
		t.Fatalf("hook rollback error = %v", err)
	}
	if _, err := f.store.UserByEmail(ctx, "dave@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rolled-back user survived: %v", err)
	}
	if _, err := f.store.SSOIdentity(ctx, identity5.ProviderConfigurationID, identity5.Issuer, identity5.Subject); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rolled-back identity survived: %v", err)
	}

	// Domain mutations fail closed while the audit stage is unavailable.
	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.store.CreateWorkspaceDomain(ctx, f.domain("blocked.example.com"), time.Time{}, f.event("domain.audit")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable create error = %v", err)
	}
	retryUser, email6, membership6, identity6 := newAccount("erin@corp.example.com", "subject-5")
	if err := f.store.JITProvisionSSOUser(ctx, retryUser, email6, membership6, identity6, f.now, f.event("jit.audit")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable JIT error = %v", err)
	}
	f.store.SetAuditFailure(nil)
}
