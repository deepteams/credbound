package credbound_test

import (
	"context"
	"errors"
	"testing"

	"github.com/deepteams/credbound"
)

// TestInstanceRoleErrorBranches exercises the validation and failure paths of
// SetInstanceRole and RemoveInstanceRole: instance-role changes are protected
// by step-up and fail closed when their audit cannot be persisted (ADMIN-004).
func TestInstanceRoleErrorBranches(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)
	local := credbound.TrustedRequest{Local: true}

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "M", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, local, member.ID, credbound.InstanceRole("nope")); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown role = %v", err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, local, "", credbound.InstanceRoleSupport); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("empty user = %v", err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, local, root.UserID, credbound.InstanceRoleSupport); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("self downgrade = %v", err)
	}
	if err := f.manager.SetInstanceRole(ctx, root, local, "0198b463-0000-7000-8000-0000000000ff", credbound.InstanceRoleSupport); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown target = %v", err)
	}
	// A non-local actor without a fresh step-up is refused (requireAdminMutation).
	if err := f.manager.SetInstanceRole(ctx, aal1(root.UserID, f.now), credbound.TrustedRequest{}, member.ID, credbound.InstanceRoleSupport); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("no step-up = %v", err)
	}
	// Audit failure on the committing path.
	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.manager.SetInstanceRole(ctx, root, local, member.ID, credbound.InstanceRoleSupport); err == nil {
		t.Fatal("set audit failure ignored")
	}
	f.store.SetAuditFailure(nil)
	if err := f.manager.SetInstanceRole(ctx, root, local, member.ID, credbound.InstanceRoleSupport); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RemoveInstanceRole(ctx, root, local, root.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("self removal = %v", err)
	}
	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.manager.RemoveInstanceRole(ctx, root, local, member.ID); err == nil {
		t.Fatal("remove audit failure ignored")
	}
	f.store.SetAuditFailure(nil)
	if err := f.manager.RemoveInstanceRole(ctx, root, local, member.ID); err != nil {
		t.Fatal(err)
	}
}

// TestMutationAuditFailures drives many committing operations while the store's
// audit write fails, covering each operation's store-error branch at once:
// every sensitive mutation fails when its audit event cannot be persisted
// atomically (AUDIT-002).
func TestMutationAuditFailures(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)
	local := credbound.TrustedRequest{Local: true}

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "M", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	pat, err := f.manager.CreatePAT(ctx, root, credbound.CreatePATInput{Name: "cli", Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := f.manager.CreateSession(ctx, root, credbound.CreateSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	live, _, err := f.manager.AuthenticateSession(ctx, session.Token)
	_ = live
	if err != nil {
		t.Fatal(err)
	}
	ws, err := f.manager.CreateWorkspace(ctx, root, credbound.CreateWorkspaceInput{Name: "Second"})
	if err != nil {
		t.Fatal(err)
	}

	f.store.SetAuditFailure(errors.New("disk full"))
	steps := map[string]func() error{
		"create user": func() error {
			_, e := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{Email: "x@example.com", DisplayName: "X", Password: "another strong password", Role: credbound.RoleMember})
			return e
		},
		"update user": func() error {
			_, e := f.manager.UpdateUser(ctx, root, credbound.UpdateUserInput{DisplayName: "Renamed"})
			return e
		},
		"disable user": func() error { return f.manager.DisableUser(ctx, root, local, member.ID) },
		"change pass": func() error {
			return f.manager.ChangePassword(ctx, root, "correct horse battery", "another strong password")
		},
		"add email": func() error { _, e := f.manager.BeginEmailAddition(ctx, root, "alias@example.com"); return e },
		"update ws": func() error {
			_, e := f.manager.UpdateWorkspace(ctx, root, ws.ID, credbound.UpdateWorkspaceInput{Name: "Renamed"})
			return e
		},
		"create pat": func() error {
			_, e := f.manager.CreatePAT(ctx, root, credbound.CreatePATInput{Name: "t", Scopes: []string{"read"}})
			return e
		},
		"revoke pat":     func() error { return f.manager.RevokePAT(ctx, root, pat.PAT.ID) },
		"revoke session": func() error { return f.manager.RevokeSession(ctx, root, session.Session.ID) },
		"begin totp":     func() error { _, e := f.manager.BeginTOTPEnrollment(ctx, root); return e },
		"set role": func() error {
			return f.manager.SetInstanceRole(ctx, root, local, member.ID, credbound.InstanceRoleSupport)
		},
		"add membership": func() error {
			_, e := f.manager.AddMembership(ctx, root, ws.ID, member.ID, credbound.RoleMember)
			return e
		},
		"revoke creds":   func() error { return f.manager.RevokeUserCredentials(ctx, root, local, member.ID) },
		"revoke sess'ns": func() error { return f.manager.RevokeUserSessions(ctx, root, local, member.ID) },
		"enable user":    func() error { return f.manager.EnableUser(ctx, root, local, member.ID) },
		"add domain":     func() error { _, e := f.manager.CreateWorkspaceDomain(ctx, root, ws.ID, "corp.example.com"); return e },
	}
	for name, step := range steps {
		if err := step(); err == nil {
			t.Fatalf("%s: expected an audit-failure error", name)
		}
	}
	f.store.SetAuditFailure(nil)
}

// TestValidationErrorAndTokenParsing covers the ValidationError.Error string,
// the requireAdminMutation unauthorized branch, and malformed-token parsing.
func TestValidationErrorAndTokenParsing(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)

	_, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "not-an-email", DisplayName: "X", Password: "another strong password", Role: credbound.RoleMember,
	})
	var validation *credbound.ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	if validation.Error() == "" || validation.Field == "" || validation.Rule == "" {
		t.Fatalf("validation error = %#v", validation)
	}

	// requireAdminMutation refuses an anonymous or non-interactive actor.
	if err := f.manager.SetInstanceRole(ctx, credbound.Authentication{}, credbound.TrustedRequest{}, authn.UserID, credbound.InstanceRoleSupport); !errors.Is(err, credbound.ErrUnauthorized) && !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("anonymous set role = %v", err)
	}

	// Malformed verification/reset tokens are rejected without a store hit.
	for _, bad := range []string{"", "cbe_bogus", "cbr_bogus", "cbe_" + authn.UserID, "prefixonly"} {
		if _, err := f.manager.ConfirmEmail(ctx, bad); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("malformed confirm %q = %v", bad, err)
		}
	}
	if _, err := f.manager.CompletePasswordReset(ctx, "not-a-token", "another strong password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("malformed reset = %v", err)
	}
}

// TestReadAndDecoyPaths covers data-export, PAT authentication edge cases, and
// the enumeration-safe decoy paths of the unauthenticated email/passkey flows:
// reset and magic-link initiation succeed without a token for unknown and
// disabled addresses instead of erroring (AUTH-006).
func TestReadAndDecoyPaths(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "M", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAAL2 := aal2(member.ID, f.now)
	if _, err := f.manager.CreatePAT(ctx, memberAAL2, credbound.CreatePATInput{Name: "cli", WorkspaceID: workspace.ID, Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateSession(ctx, memberAAL2, credbound.CreateSessionInput{}); err != nil {
		t.Fatal(err)
	}

	// Export the member's data (root has users read).
	export, err := f.manager.ExportUserData(ctx, root, member.ID)
	if err != nil || export.User.ID != member.ID || len(export.Emails) == 0 {
		t.Fatalf("export = %#v, %v", export, err)
	}

	// PAT authentication rejects malformed, unknown and forged tokens.
	for _, bad := range []string{"", "nope", "cbp_bogus", "cbp_" + member.ID + "_short"} {
		if _, err := f.manager.AuthenticatePAT(ctx, bad); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("bad PAT %q = %v", bad, err)
		}
	}

	// Decoy paths: unknown and disabled addresses answer without a token and
	// without an error.
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"ghost@example.com", "member@example.com"} {
		if reset, err := f.manager.BeginPasswordReset(ctx, address); err != nil || reset.Token != "" {
			t.Fatalf("reset decoy %q = %#v, %v", address, reset, err)
		}
		if link, err := f.manager.BeginEmailAuthentication(ctx, address); err != nil || link.Token != "" {
			t.Fatalf("magic-link decoy %q = %#v, %v", address, link, err)
		}
		if _, err := f.manager.BeginEmailOTP(ctx, address); err != nil {
			t.Fatalf("otp decoy %q = %v", address, err)
		}
		if _, err := f.manager.BeginPasskeyAuthentication(ctx, address); err != nil {
			t.Fatalf("passkey decoy %q = %v", address, err)
		}
	}
}

// TestPATLifecycleAndExportBranches covers PAT authentication over a token's
// lifecycle and ExportUserData authorization and content branches.
func TestPATLifecycleAndExportBranches(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	ctx := context.Background()
	root := aal2(authn.UserID, f.now)

	member, err := f.manager.CreateUser(ctx, root, workspace.ID, credbound.CreateUserInput{
		Email: "member@example.com", DisplayName: "M", Password: "another strong password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberAAL2 := aal2(member.ID, f.now)
	issued, err := f.manager.CreatePAT(ctx, memberAAL2, credbound.CreatePATInput{Name: "cli", WorkspaceID: workspace.ID, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	// A valid PAT authenticates.
	principal, err := f.manager.AuthenticatePAT(ctx, issued.Token)
	if err != nil || principal.UserID != member.ID {
		t.Fatalf("valid PAT = %#v, %v", principal, err)
	}
	// Self-export requires a recent interactive authentication and returns the
	// caller's own record.
	if export, err := f.manager.ExportUserData(ctx, memberAAL2, ""); err != nil || export.User.ID != member.ID {
		t.Fatalf("self export = %#v, %v", export, err)
	}
	// A member cannot export another user's data.
	if _, err := f.manager.ExportUserData(ctx, memberAAL2, authn.UserID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("cross-user export = %v", err)
	}
	// After revocation the PAT no longer authenticates.
	if err := f.manager.RevokePAT(ctx, memberAAL2, issued.PAT.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePAT(ctx, issued.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("revoked PAT = %v", err)
	}
	// A PAT of a disabled user is refused.
	other, err := f.manager.CreatePAT(ctx, memberAAL2, credbound.CreatePATInput{Name: "cli2", WorkspaceID: workspace.ID, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.DisableUser(ctx, root, credbound.TrustedRequest{Local: true}, member.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePAT(ctx, other.Token); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("disabled-user PAT = %v", err)
	}
}
