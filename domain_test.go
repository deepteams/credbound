package credbound_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
	"golang.org/x/net/idna"
)

const (
	domainProviderA = "0198b463-0000-7000-8000-0000000000aa"
	domainProviderB = "0198b463-0000-7000-8000-0000000000ab"
)

type domainRecorder struct {
	credbound.UnimplementedEventListener
	created        []credbound.WorkspaceDomainEvent
	confirmed      []credbound.WorkspaceDomainEvent
	policyUpdated  []credbound.WorkspaceDomainEvent
	removed        []credbound.WorkspaceDomainEvent
	jitProvisioned []credbound.SSOJITProvisionedEvent
	usersCreated   []credbound.UserCreatedEvent
	ssoLinked      []credbound.SSOLinkedEvent
}

func (r *domainRecorder) OnWorkspaceDomainCreated(_ context.Context, event credbound.WorkspaceDomainEvent) error {
	r.created = append(r.created, event)
	return nil
}

func (r *domainRecorder) OnWorkspaceDomainConfirmed(_ context.Context, event credbound.WorkspaceDomainEvent) error {
	r.confirmed = append(r.confirmed, event)
	return nil
}

func (r *domainRecorder) OnWorkspaceDomainPolicyUpdated(_ context.Context, event credbound.WorkspaceDomainEvent) error {
	r.policyUpdated = append(r.policyUpdated, event)
	return nil
}

func (r *domainRecorder) OnWorkspaceDomainRemoved(_ context.Context, event credbound.WorkspaceDomainEvent) error {
	r.removed = append(r.removed, event)
	return nil
}

func (r *domainRecorder) OnSSOJITProvisioned(_ context.Context, event credbound.SSOJITProvisionedEvent) error {
	r.jitProvisioned = append(r.jitProvisioned, event)
	return nil
}

func (r *domainRecorder) OnUserCreated(_ context.Context, event credbound.UserCreatedEvent) error {
	r.usersCreated = append(r.usersCreated, event)
	return nil
}

func (r *domainRecorder) OnSSOLinked(_ context.Context, event credbound.SSOLinkedEvent) error {
	r.ssoLinked = append(r.ssoLinked, event)
	return nil
}

func collectDomains(t *testing.T, sequence func(func(credbound.PageEvent[credbound.WorkspaceDomain], error) bool)) ([]credbound.WorkspaceDomain, *credbound.PageEnd) {
	t.Helper()
	var items []credbound.WorkspaceDomain
	var end *credbound.PageEnd
	for event, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}
		if event.Data != nil {
			items = append(items, *event.Data)
		}
		if event.End != nil {
			end = event.End
		}
	}
	return items, end
}

func domainsError(sequence func(func(credbound.PageEvent[credbound.WorkspaceDomain], error) bool)) error {
	for _, err := range sequence {
		return err
	}
	return nil
}

func jitProvider(subject, email string, verified bool) *fakeSSOProvider {
	return &fakeSSOProvider{
		configurationID: domainProviderA, kind: credbound.SSOProviderOIDC,
		claims: credbound.SSOClaims{Issuer: "https://idp.example.com", Subject: subject, Email: email, EmailVerified: verified},
	}
}

// TestWorkspaceDomainStaleClaimDisplaced guards the anti-squat rule: a
// pending claim left unconfirmed past Config.DomainClaimTTL loses its
// reservation to a new claim from any workspace, while a confirmed domain
// keeps its name forever.
func TestWorkspaceDomainStaleClaimDisplaced(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	squatted, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "victim.example.com")
	if err != nil {
		t.Fatal(err)
	}
	kept, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "kept.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, kept.Domain.ID); err != nil {
		t.Fatal(err)
	}
	other, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Rightful Owner"})
	if err != nil {
		t.Fatal(err)
	}
	// Within the claim window the pending name is defended.
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, other.ID, "victim.example.com"); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("fresh pending claim displaced = %v", err)
	}
	f.now = f.now.Add(7*24*time.Hour + time.Minute)
	lateStepUp := aal2(authn.UserID, f.now)
	reclaimed, err := f.manager.CreateWorkspaceDomain(ctx, lateStepUp, other.ID, "victim.example.com")
	if err != nil || reclaimed.Domain.WorkspaceID != other.ID {
		t.Fatalf("stale claim displacement = %#v, %v", reclaimed, err)
	}
	if _, err := f.store.WorkspaceDomainByID(ctx, squatted.Domain.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("displaced claim survived: %v", err)
	}
	// A confirmed domain never expires, however old.
	if _, err := f.manager.CreateWorkspaceDomain(ctx, lateStepUp, other.ID, "kept.example.com"); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("confirmed domain displaced = %v", err)
	}
}

func TestWorkspaceDomainLifecycle(t *testing.T) {
	provider := jitProvider("subject-1", "alice@corp.example.com", true)
	f := newFixture(t, provider)
	recorder := &domainRecorder{}
	f.manager.AddEventListener(recorder)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	issued, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, " Corp.Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	domain := issued.Domain
	if !uuidV7.MatchString(domain.ID) || domain.WorkspaceID != workspace.ID || domain.Domain != "corp.example.com" {
		t.Fatalf("issued domain = %#v", domain)
	}
	if issued.Challenge != domain.Challenge || !strings.HasPrefix(issued.Challenge, "credbound-domain-verification=") ||
		len(strings.TrimPrefix(issued.Challenge, "credbound-domain-verification=")) != 43 {
		t.Fatalf("challenge = %q", issued.Challenge)
	}
	if domain.ConfirmedAt != nil || domain.AutoJoin || domain.EnforceSSO {
		t.Fatalf("new domain not pending: %#v", domain)
	}
	if len(recorder.created) != 1 || recorder.created[0].Domain.ID != domain.ID || recorder.created[0].Name != credbound.EventWorkspaceDomainCreated {
		t.Fatalf("created event = %#v", recorder.created)
	}

	// The name is unique across all workspaces, whatever the case.
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "CORP.example.com"); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("duplicate domain error = %v", err)
	}
	other, err := f.manager.CreateWorkspace(ctx, stepUp, credbound.CreateWorkspaceInput{Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, other.ID, "corp.example.com"); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("cross-workspace duplicate error = %v", err)
	}

	// Policy is refused while the domain is pending, and the challenge stays
	// visible on the listed record so the host can re-display the TXT value.
	policy := credbound.WorkspaceDomainPolicyInput{AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, policy); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("pending policy error = %v", err)
	}
	listed, end := collectDomains(t, f.manager.WorkspaceDomains(ctx, authn, workspace.ID, credbound.PageRequest{}))
	if len(listed) != 1 || listed[0].Challenge != issued.Challenge || end == nil || end.HasMore {
		t.Fatalf("domain list = %#v, %#v", listed, end)
	}

	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, "0198b463-0000-7000-8000-00000000dead"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("unknown domain confirm error = %v", err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, "not-a-uuid"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid domain id error = %v", err)
	}
	f.now = f.now.Add(time.Minute)
	stepUp.AuthenticatedAt = f.now
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, domain.ID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("double confirm error = %v", err)
	}
	if len(recorder.confirmed) != 1 || recorder.confirmed[0].Domain.ConfirmedAt == nil {
		t.Fatalf("confirmed event = %#v", recorder.confirmed)
	}

	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, AutoJoinRole: credbound.Role("ghost"), SSOProviderConfigurationID: domainProviderA,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unknown role error = %v", err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderB,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("unregistered provider error = %v", err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, credbound.WorkspaceDomainPolicyInput{
		EnforceSSO: true,
	}); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("enforcement without provider error = %v", err)
	}
	var validation *credbound.ValidationError
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true,
	}); !errors.As(err, &validation) || validation.Field != "sso_provider_configuration_id" {
		t.Fatalf("provider validation error = %v", err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, domain.ID, policy); err != nil {
		t.Fatal(err)
	}
	if len(recorder.policyUpdated) != 1 || !recorder.policyUpdated[0].Domain.AutoJoin ||
		recorder.policyUpdated[0].Domain.AutoJoinRole != credbound.RoleMember || !recorder.policyUpdated[0].Domain.EnforceSSO {
		t.Fatalf("policy event = %#v", recorder.policyUpdated)
	}
	listed, _ = collectDomains(t, f.manager.WorkspaceDomains(ctx, authn, workspace.ID, credbound.PageRequest{}))
	if len(listed) != 1 || !listed[0].AutoJoin || listed[0].AutoJoinRole != credbound.RoleMember ||
		listed[0].SSOProviderConfigurationID != domainProviderA || !listed[0].EnforceSSO || listed[0].ConfirmedAt == nil {
		t.Fatalf("confirmed listing = %#v", listed)
	}

	if err := f.manager.RemoveWorkspaceDomain(ctx, stepUp, domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.RemoveWorkspaceDomain(ctx, stepUp, domain.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("double remove error = %v", err)
	}
	if len(recorder.removed) != 1 {
		t.Fatalf("removed event = %#v", recorder.removed)
	}
	listed, _ = collectDomains(t, f.manager.WorkspaceDomains(ctx, authn, workspace.ID, credbound.PageRequest{}))
	if len(listed) != 0 {
		t.Fatalf("domains after removal = %#v", listed)
	}
	// A removed name is free again.
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkspaceDomainValidationAndAuthorization(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	var validation *credbound.ValidationError
	for _, invalid := range []string{
		"", "   ", "nodot", "example..com", ".example.com", "example.com.",
		"-bad.example.com", "bad-.example.com", "under_score.example.com",
		"spaced domain.example.com", "192.168.0.1",
		strings.Repeat("a", 64) + ".example.com",
		strings.Repeat("abcdefgh.", 30) + "example.com",
		// Bare public suffixes are not registrable domains.
		"co.uk", "com.au", "github.io",
	} {
		_, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, invalid)
		if !errors.Is(err, credbound.ErrInvalidInput) || !errors.As(err, &validation) || validation.Field != "domain" {
			t.Fatalf("domain %q error = %v", invalid, err)
		}
	}

	if _, err := f.manager.CreateWorkspaceDomain(ctx, authn, workspace.ID, "corp.example.com"); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 create error = %v", err)
	}
	if _, err := f.manager.CreateWorkspaceDomain(ctx, credbound.Authentication{}, workspace.ID, "corp.example.com"); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous create error = %v", err)
	}

	member, err := f.manager.CreateUser(ctx, stepUp, workspace.ID, credbound.CreateUserInput{
		Email: "member@member.example", DisplayName: "Member", Password: "another secure password", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	memberStepUp := aal2(member.ID, f.now)
	if _, err := f.manager.CreateWorkspaceDomain(ctx, memberStepUp, workspace.ID, "corp.example.com"); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member create error = %v", err)
	}

	issued, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, memberStepUp, issued.Domain.ID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member confirm error = %v", err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, authn, issued.Domain.ID); !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 confirm error = %v", err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, memberStepUp, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{}); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member policy error = %v", err)
	}
	if err := f.manager.RemoveWorkspaceDomain(ctx, memberStepUp, issued.Domain.ID); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("member remove error = %v", err)
	}

	// Any active member reads the listing; an outsider does not.
	if memberListed, _ := collectDomains(t, f.manager.WorkspaceDomains(ctx, aal2(member.ID, f.now), workspace.ID, credbound.PageRequest{})); len(memberListed) != 1 {
		t.Fatalf("member listing = %#v", memberListed)
	}
	if err := domainsError(f.manager.WorkspaceDomains(ctx, credbound.Authentication{}, workspace.ID, credbound.PageRequest{})); !errors.Is(err, credbound.ErrUnauthorized) {
		t.Fatalf("anonymous list error = %v", err)
	}
	if err := domainsError(f.manager.WorkspaceDomains(ctx, stepUp, workspace.ID, credbound.PageRequest{Limit: -1})); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid page error = %v", err)
	}
	outsider, err := f.manager.CreateWorkspace(ctx, aal2(authn.UserID, f.now), credbound.CreateWorkspaceInput{Name: "Elsewhere"})
	if err != nil {
		t.Fatal(err)
	}
	if err := domainsError(f.manager.WorkspaceDomains(ctx, aal2(member.ID, f.now), outsider.ID, credbound.PageRequest{})); !errors.Is(err, credbound.ErrForbidden) {
		t.Fatalf("outsider list error = %v", err)
	}
}

func TestDomainEnforcedSSO(t *testing.T) {
	provider := jitProvider("subject-1", "root@example.com", true)
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	issued, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	// An unconfirmed domain has no effect, even after a policy would enforce.
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("pending domain blocked login: %v", err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	// A confirmed domain without enforcement changes nothing either.
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("non-enforced domain blocked login: %v", err)
	}

	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Existing and nonexistent accounts under the domain answer identically.
	for _, email := range []string{"root@example.com", "ROOT@Example.com ", "ghost@example.com"} {
		if _, err := f.manager.AuthenticatePassword(ctx, email, "correct horse battery"); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("password %q error = %v", email, err)
		}
		if _, err := f.manager.BeginPasswordReset(ctx, email); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("reset %q error = %v", email, err)
		}
		if _, err := f.manager.BeginEmailAuthentication(ctx, email); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("magic link %q error = %v", email, err)
		}
		if _, err := f.manager.BeginEmailOTP(ctx, email); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("email OTP %q error = %v", email, err)
		}
		if _, err := f.manager.BeginPasskeyAuthentication(ctx, email); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("passkey %q error = %v", email, err)
		}
	}
	// Addresses outside the domain keep their exact previous behavior.
	if _, err := f.manager.AuthenticatePassword(ctx, "ghost@other.example", "whatever password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("foreign password error = %v", err)
	}
	if reset, err := f.manager.BeginPasswordReset(ctx, "ghost@other.example"); err != nil || reset.Token != "" {
		t.Fatalf("foreign reset = %#v, %v", reset, err)
	}
	// An invitation must not carve a password account onto an SSO-enforced
	// domain: RegisterFromInvitation is refused just like signup and password
	// authentication.
	invite, err := f.manager.InviteToWorkspace(ctx, stepUp, workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.manager.RegisterFromInvitation(ctx, invite.Token, credbound.RegisterFromInvitationInput{
		DisplayName: "Invitee", Password: "chosen by invitee strong",
	}); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("invitation register on SSO-enforced domain = %v", err)
	}
	// Resending an email verification for an SSO-enforced domain is refused up
	// front, like signup and password reset.
	if _, err := f.manager.ResendEmailVerification(ctx, "someone@example.com"); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("resend verification on SSO-enforced domain = %v", err)
	}
	// Removing the domain lifts enforcement immediately.
	if err := f.manager.RemoveWorkspaceDomain(ctx, aal2(authn.UserID, f.now), issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.AuthenticatePassword(ctx, "root@example.com", "correct horse battery"); err != nil {
		t.Fatalf("post-removal login error = %v", err)
	}
}

// TestDomainEnforcedSSOInFlightCeremonies proves enforcement at redemption:
// a ceremony issued before EnforceSSO is confirmed must be refused when it is
// consumed after, otherwise the policy only binds sign-ins started after the
// switch and every in-flight token remains a working non-SSO login.
func TestDomainEnforcedSSOInFlightCeremonies(t *testing.T) {
	provider := jitProvider("subject-1", "root@example.com", true)
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	challenge, err := f.manager.BeginPasskeyRegistration(ctx, stepUp, "MacBook")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishPasskeyRegistration(ctx, stepUp, challenge.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}

	// Every ceremony starts while the domain is unenforced.
	link, err := f.manager.BeginEmailAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	otp, err := f.manager.BeginEmailOTP(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	passkeyLogin, err := f.manager.BeginPasskeyAuthentication(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}
	reset, err := f.manager.BeginPasswordReset(ctx, "root@example.com")
	if err != nil {
		t.Fatal(err)
	}

	issued, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Redeeming any of them now answers the enforcement sentinel.
	if _, err := f.manager.CompleteEmailAuthentication(ctx, link.Token); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("in-flight magic link error = %v", err)
	}
	if _, err := f.manager.CompleteEmailOTP(ctx, otp.Continuation, otp.Code); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("in-flight email OTP error = %v", err)
	}
	if _, err := f.manager.FinishPasskeyAuthentication(ctx, passkeyLogin.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("in-flight passkey ceremony error = %v", err)
	}
	if _, err := f.manager.CompletePasswordReset(ctx, reset.Token, "fresh account password"); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("in-flight password reset error = %v", err)
	}
}

func setupJITDomain(t *testing.T, f *fixture, workspaceID string, actor credbound.Authentication, policy credbound.WorkspaceDomainPolicyInput) credbound.WorkspaceDomain {
	t.Helper()
	ctx := context.Background()
	issued, err := f.manager.CreateWorkspaceDomain(ctx, actor, workspaceID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, actor, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, actor, issued.Domain.ID, policy); err != nil {
		t.Fatal(err)
	}
	return issued.Domain
}

func TestSSOJITProvisioningHappyPath(t *testing.T) {
	provider := jitProvider("subject-jit", "Alice@Corp.Example.com", true)
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	recorder := &domainRecorder{}
	f.manager.AddEventListener(recorder)
	domain := setupJITDomain(t, f, workspace.ID, aal2(authn.UserID, f.now), credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true,
	})

	challenge, err := f.manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	provisioned, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	if provisioned.Method != credbound.MethodSSO || provisioned.Level != credbound.AAL2 || !uuidV7.MatchString(provisioned.UserID) {
		t.Fatalf("JIT authentication = %#v", provisioned)
	}
	user, err := f.store.UserByEmail(ctx, "alice@corp.example.com")
	if err != nil || user.ID != provisioned.UserID || user.LastSeenAt == nil || !user.LastSeenAt.Equal(f.now) {
		t.Fatalf("JIT user = %#v, %v", user, err)
	}
	// The account is passwordless: no credential exists and password sign-in
	// is rejected by the enforced domain anyway.
	if _, err := f.store.PasswordByUserID(ctx, user.ID); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("JIT password credential error = %v", err)
	}
	membership, err := f.store.Membership(ctx, workspace.ID, user.ID)
	if err != nil || membership.Role != credbound.RoleMember || membership.Status != credbound.MembershipActive ||
		membership.ProvisioningSource != "jit:"+domain.ID {
		t.Fatalf("JIT membership = %#v, %v", membership, err)
	}
	identities := collectSSOIdentities(t, f.manager.SSOIdentities(ctx, provisioned, "", credbound.PageRequest{}))
	if len(identities) != 1 || identities[0].Subject != "subject-jit" || identities[0].Email != "alice@corp.example.com" {
		t.Fatalf("JIT identities = %#v", identities)
	}
	// The passwordless member cannot unlink their only authentication method
	// and lock themselves out.
	if err := f.manager.UnlinkSSO(ctx, provisioned, identities[0].ID); !errors.Is(err, credbound.ErrConflict) {
		t.Fatalf("last-method unlink = %v", err)
	}
	if len(recorder.usersCreated) != 1 || recorder.usersCreated[0].Email.VerifiedAt == nil || !recorder.usersCreated[0].Email.Primary {
		t.Fatalf("user.created event = %#v", recorder.usersCreated)
	}
	if len(recorder.ssoLinked) != 1 || len(recorder.jitProvisioned) != 1 {
		t.Fatalf("SSO events = %#v / %#v", recorder.ssoLinked, recorder.jitProvisioned)
	}
	if recorder.jitProvisioned[0].DomainID != domain.ID || recorder.jitProvisioned[0].Membership.WorkspaceID != workspace.ID {
		t.Fatalf("jit event = %#v", recorder.jitProvisioned[0])
	}

	// The next ceremony resolves the linked identity through the normal
	// sign-in path.
	again, err := f.manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	repeat, err := f.manager.FinishSSO(ctx, again.Continuation, []byte("valid"))
	if err != nil || repeat.UserID != provisioned.UserID {
		t.Fatalf("repeat SSO login = %#v, %v", repeat, err)
	}
	if len(recorder.usersCreated) != 1 {
		t.Fatalf("repeat login provisioned again: %#v", recorder.usersCreated)
	}
}

func TestSSOJITRefusals(t *testing.T) {
	finishLogin := func(t *testing.T, f *fixture) error {
		t.Helper()
		challenge, err := f.manager.BeginSSO(context.Background(), domainProviderA)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.manager.FinishSSO(context.Background(), challenge.Continuation, []byte("valid"))
		return err
	}
	newCase := func(t *testing.T, provider *fakeSSOProvider, policy credbound.WorkspaceDomainPolicyInput) (*fixture, credbound.Authentication, credbound.Workspace) {
		t.Helper()
		second := &fakeSSOProvider{configurationID: domainProviderB, kind: credbound.SSOProviderOIDC, claims: provider.claims}
		f := newFixture(t, provider, second)
		authn, workspace := f.bootstrap(t)
		setupJITDomain(t, f, workspace.ID, aal2(authn.UserID, f.now), policy)
		return f, authn, workspace
	}
	autoJoin := credbound.WorkspaceDomainPolicyInput{AutoJoin: true, SSOProviderConfigurationID: domainProviderA}

	t.Run("existing account is never auto-linked", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		f, authn, workspace := newCase(t, provider, autoJoin)
		if _, err := f.manager.CreateUser(context.Background(), aal2(authn.UserID, f.now), workspace.ID, credbound.CreateUserInput{
			Email: "alice@corp.example.com", DisplayName: "Alice", Password: "another secure password", Role: credbound.RoleMember,
		}); err != nil {
			t.Fatal(err)
		}
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("existing account JIT error = %v", err)
		}
	})

	t.Run("provider configuration must match the policy", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		f, _, _ := newCase(t, provider, credbound.WorkspaceDomainPolicyInput{AutoJoin: true, SSOProviderConfigurationID: domainProviderB})
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("wrong provider JIT error = %v", err)
		}
	})

	t.Run("auto-join disabled", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		f, _, _ := newCase(t, provider, credbound.WorkspaceDomainPolicyInput{SSOProviderConfigurationID: domainProviderA, EnforceSSO: true})
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("auto-join off JIT error = %v", err)
		}
	})

	t.Run("unverified email", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", false)
		f, _, _ := newCase(t, provider, autoJoin)
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("unverified email JIT error = %v", err)
		}
	})

	t.Run("missing email", func(t *testing.T) {
		provider := jitProvider("subject-1", "", true)
		f, _, _ := newCase(t, provider, autoJoin)
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("missing email JIT error = %v", err)
		}
	})

	t.Run("domain outside any policy", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@elsewhere.example", true)
		f, _, _ := newCase(t, provider, autoJoin)
		if err := finishLogin(t, f); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("foreign domain JIT error = %v", err)
		}
	})

	t.Run("step-up ceremony never provisions", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		f, authn, _ := newCase(t, provider, autoJoin)
		ctx := context.Background()
		challenge, err := f.manager.BeginSSOStepUp(ctx, authn, domainProviderA)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("step-up JIT error = %v", err)
		}
		if _, err := f.store.UserByEmail(ctx, "alice@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
			t.Fatalf("step-up ceremony provisioned a user: %v", err)
		}
	})

	t.Run("link ceremony keeps explicit linking", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		f, authn, _ := newCase(t, provider, autoJoin)
		ctx := context.Background()
		challenge, err := f.manager.BeginSSOLink(ctx, authn, domainProviderA)
		if err != nil {
			t.Fatal(err)
		}
		linked, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid"))
		if err != nil || linked.UserID != authn.UserID {
			t.Fatalf("explicit link = %#v, %v", linked, err)
		}
		if _, err := f.store.UserByEmail(ctx, "alice@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
			t.Fatalf("link ceremony provisioned a user: %v", err)
		}
	})

	t.Run("no domain capability", func(t *testing.T) {
		provider := jitProvider("subject-1", "alice@corp.example.com", true)
		limited, err := credbound.New(credbound.Config{
			Store: coreStore{Store: memory.New()}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
			SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
			SSOProviders: []credbound.SSOProvider{provider},
		})
		if err != nil {
			t.Fatal(err)
		}
		challenge, err := limited.BeginSSO(context.Background(), domainProviderA)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := limited.FinishSSO(context.Background(), challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
			t.Fatalf("capability-less JIT error = %v", err)
		}
	})
}

func TestWorkspaceDomainNotSupported(t *testing.T) {
	limited, err := credbound.New(credbound.Config{
		Store: coreStore{Store: memory.New()}, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := aal2("0198b463-0000-7000-8000-0000000000aa", time.Now())
	workspaceID := "0198b463-0000-7000-8000-0000000000ab"
	domainID := "0198b463-0000-7000-8000-0000000000ac"
	if _, err := limited.CreateWorkspaceDomain(ctx, actor, workspaceID, "corp.example.com"); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("create error = %v", err)
	}
	if err := limited.ConfirmWorkspaceDomain(ctx, actor, domainID); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("confirm error = %v", err)
	}
	if err := limited.UpdateWorkspaceDomainPolicy(ctx, actor, domainID, credbound.WorkspaceDomainPolicyInput{}); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("policy error = %v", err)
	}
	if err := limited.RemoveWorkspaceDomain(ctx, actor, domainID); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("remove error = %v", err)
	}
	if err := domainsError(limited.WorkspaceDomains(ctx, actor, workspaceID, credbound.PageRequest{})); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("list error = %v", err)
	}
	// Without the capability the enforcement check is free and authentication
	// keeps its exact behavior.
	if _, err := limited.AuthenticatePassword(ctx, "ghost@example.com", "whatever password"); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("capability-less password error = %v", err)
	}
}

// jitConflictStore simulates a registration racing the JIT transaction: the
// pre-commit lookups see nothing but the atomic provision hits a conflict.
type jitConflictStore struct {
	*memory.Store
}

func (s *jitConflictStore) JITProvisionSSOUser(context.Context, credbound.User, credbound.EmailAddress, credbound.Membership, credbound.SSOIdentity, time.Time, credbound.Commit) error {
	return credbound.ErrConflict
}

func TestSSOJITConflictRaceFailsAsUnknownIdentity(t *testing.T) {
	provider := jitProvider("subject-1", "alice@corp.example.com", true)
	store := &jitConflictStore{Store: memory.New()}
	manager, err := credbound.New(credbound.Config{
		Store: store, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		SSOProviders:                 []credbound.SSOProvider{provider},
		TrustActorDomainVerification: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	authn, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@root.example", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	stepUp := aal2(authn.UserID, time.Now())
	issued, err := manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConfirmWorkspaceDomain(ctx, stepUp, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA,
	}); err != nil {
		t.Fatal(err)
	}
	challenge, err := manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("racing JIT error = %v", err)
	}
}

// domainFaultStore injects lookup failures around the embedded memory
// store's domain capability.
type domainFaultStore struct {
	*memory.Store
	confirmedByNameErr error
}

func (s *domainFaultStore) ConfirmedWorkspaceDomainByName(ctx context.Context, name string) (credbound.WorkspaceDomain, error) {
	if s.confirmedByNameErr != nil {
		return credbound.WorkspaceDomain{}, s.confirmedByNameErr
	}
	return s.Store.ConfirmedWorkspaceDomainByName(ctx, name)
}

type domainHook struct {
	credbound.UnimplementedTransactionHook
	domainErr error
	userErr   error
}

func (h *domainHook) ApplyWorkspaceDomainChange(context.Context, credbound.Tx, credbound.WorkspaceDomainChange) error {
	return h.domainErr
}

func (h *domainHook) ApplyUserCreate(context.Context, credbound.Tx, credbound.UserCreateChange) error {
	return h.userErr
}

func TestWorkspaceDomainAuditAndFaultPaths(t *testing.T) {
	provider := jitProvider("subject-1", "alice@corp.example.com", true)
	f := newFixture(t, provider)
	hook := &domainHook{}
	f.manager.AddTransactionHook(hook)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)

	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable create = %v", err)
	}
	f.store.SetAuditFailure(nil)

	// A hook rejection aborts the whole commit.
	hook.domainErr = errors.New("outbox unavailable")
	if _, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com"); !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("hook-rejected create = %v", err)
	}
	hook.domainErr = nil
	issued, err := f.manager.CreateWorkspaceDomain(ctx, stepUp, workspace.ID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}

	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, issued.Domain.ID); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable confirm = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if err := f.manager.ConfirmWorkspaceDomain(ctx, stepUp, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	policy := credbound.WorkspaceDomainPolicyInput{AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true}
	f.store.SetAuditFailure(errors.New("disk full"))
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, policy); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable policy = %v", err)
	}
	if err := f.manager.RemoveWorkspaceDomain(ctx, stepUp, issued.Domain.ID); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable remove = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, stepUp, issued.Domain.ID, policy); err != nil {
		t.Fatal(err)
	}

	// An enforcement rejection that cannot be audited fails closed.
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.AuthenticatePassword(ctx, "ghost@corp.example.com", "whatever password"); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("unauditable enforcement = %v", err)
	}
	f.store.SetAuditFailure(nil)

	// A hook failure inside the JIT transaction rolls the whole account back.
	hook.userErr = errors.New("outbox unavailable")
	challenge, err := f.manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("hook-rejected JIT = %v", err)
	}
	if _, err := f.store.UserByEmail(ctx, "alice@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("JIT survived hook rollback: %v", err)
	}
	hook.userErr = nil
	challenge, err = f.manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	// The whole JIT commit fails closed while the audit stage is unavailable.
	f.store.SetAuditFailure(errors.New("disk full"))
	if _, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrAuditUnavailable) {
		t.Fatalf("audit-unavailable JIT = %v", err)
	}
	f.store.SetAuditFailure(nil)
	if _, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); err != nil {
		t.Fatal(err)
	}

	// Infrastructure failures of the hot domain lookup propagate unchanged.
	fault := &domainFaultStore{Store: memory.New(), confirmedByNameErr: errors.New("index offline")}
	faulty, err := credbound.New(credbound.Config{
		Store: fault, Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		SSOProviders: []credbound.SSOProvider{jitProvider("subject-1", "alice@corp.example.com", true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := faulty.AuthenticatePassword(ctx, "ghost@corp.example.com", "whatever password"); err == nil || !strings.Contains(err.Error(), "index offline") {
		t.Fatalf("fault propagation = %v", err)
	}
	faultChallenge, err := faulty.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := faulty.FinishSSO(ctx, faultChallenge.Continuation, []byte("valid")); err == nil || !strings.Contains(err.Error(), "index offline") {
		t.Fatalf("JIT fault propagation = %v", err)
	}
}

func TestSSOJITRefusedOnDisabledWorkspace(t *testing.T) {
	provider := jitProvider("subject-disabled-ws", "bob@corp.example.com", true)
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)
	setupJITDomain(t, f, workspace.ID, stepUp, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA,
	})
	if err := f.manager.DisableWorkspace(ctx, stepUp, workspace.ID); err != nil {
		t.Fatal(err)
	}
	challenge, err := f.manager.BeginSSO(ctx, domainProviderA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.FinishSSO(ctx, challenge.Continuation, []byte("valid")); !errors.Is(err, credbound.ErrInvalidCredentials) {
		t.Fatalf("JIT into disabled workspace = %v", err)
	}
	if _, err := f.store.UserByEmail(ctx, "bob@corp.example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("disabled workspace still provisioned a user: %v", err)
	}
}

func TestDomainEnforcedSSOBlocksSignup(t *testing.T) {
	provider := jitProvider("subject-signup", "root@example.com", true)
	f := newFixture(t, provider)
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	stepUp := aal2(authn.UserID, f.now)
	setupJITDomain(t, f, workspace.ID, stepUp, credbound.WorkspaceDomainPolicyInput{
		AutoJoin: true, SSOProviderConfigurationID: domainProviderA, EnforceSSO: true,
	})

	// A second manager sharing the store enables self-service signup; the
	// enforced domain must refuse a password signup that could never sign in.
	signup, err := credbound.New(credbound.Config{
		Store: f.store, Passwords: f.passwords, TOTP: fakeTOTP{}, Passkeys: f.passkeys,
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return f.now }, Random: &counterReader{next: 0x51},
		SignUp: &credbound.SignUpConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signup.SignUp(ctx, credbound.SignUpInput{
		Email: "newcomer@corp.example.com", DisplayName: "Newcomer",
		Password: "another strong password", WorkspaceName: "Side project",
	}); !errors.Is(err, credbound.ErrSSORequired) {
		t.Fatalf("signup under enforced domain = %v", err)
	}
	if _, err := signup.SignUp(ctx, credbound.SignUpInput{
		Email: "newcomer@elsewhere.example", DisplayName: "Newcomer",
		Password: "another strong password", WorkspaceName: "Side project",
	}); err != nil {
		t.Fatalf("signup outside enforced domain = %v", err)
	}
}

// fakeDomainVerifier proves domain control against a fixed expected challenge,
// standing in for a real DNS TXT lookup.
type fakeDomainVerifier struct {
	fail          bool
	seenDomain    string
	seenChallenge string
}

func (v *fakeDomainVerifier) VerifyDomain(_ context.Context, domain, challenge string) error {
	v.seenDomain, v.seenChallenge = domain, challenge
	if v.fail {
		return errors.New("challenge not published in DNS")
	}
	return nil
}

// TestConfirmWorkspaceDomainRequiresVerifierOrOptIn locks the fail-closed
// default: without a DomainVerifier and without the explicit
// TrustActorDomainVerification opt-in, confirmation refuses.
func TestConfirmWorkspaceDomainRequiresVerifierOrOptIn(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x73},
		StepUpMaxAge: 10 * time.Minute, CeremonyTTL: 5 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := aal2(root.UserID, now)
	issued, err := manager.CreateWorkspaceDomain(ctx, actor, workspace.ID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ConfirmWorkspaceDomain(ctx, actor, issued.Domain.ID); !errors.Is(err, credbound.ErrNotSupported) {
		t.Fatalf("confirmation without verifier or opt-in = %v", err)
	}
}

func TestConfirmWorkspaceDomainVerifier(t *testing.T) {
	verifier := &fakeDomainVerifier{fail: true}
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	manager, err := credbound.New(credbound.Config{
		Store: memory.New(), Passwords: &fakePasswords{}, TOTP: fakeTOTP{}, Passkeys: &fakePasskeys{},
		SecretKey: bytesOf(1, 32), PATPepper: bytesOf(2, 32), RecoveryPepper: bytesOf(3, 32),
		Clock: func() time.Time { return now }, Random: &counterReader{next: 0x71},
		StepUpMaxAge: 10 * time.Minute, CeremonyTTL: 5 * time.Minute,
		DomainVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	root, workspace, err := manager.Bootstrap(ctx, credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := aal2(root.UserID, now)
	issued, err := manager.CreateWorkspaceDomain(ctx, actor, workspace.ID, "corp.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// A failing verifier refuses confirmation and the domain stays pending.
	if err := manager.ConfirmWorkspaceDomain(ctx, actor, issued.Domain.ID); !errors.Is(err, credbound.ErrDomainVerification) {
		t.Fatalf("unverified confirm error = %v", err)
	}
	if verifier.seenDomain != "corp.example.com" || verifier.seenChallenge != issued.Challenge {
		t.Fatalf("verifier saw %q/%q, want %q/%q", verifier.seenDomain, verifier.seenChallenge, "corp.example.com", issued.Challenge)
	}
	if listed, _ := collectDomains(t, manager.WorkspaceDomains(ctx, actor, workspace.ID, credbound.PageRequest{})); len(listed) != 1 || listed[0].ConfirmedAt != nil {
		t.Fatalf("domain confirmed despite failed verification: %#v", listed)
	}

	// Once ownership is proven, confirmation succeeds.
	verifier.fail = false
	if err := manager.ConfirmWorkspaceDomain(ctx, actor, issued.Domain.ID); err != nil {
		t.Fatalf("verified confirm = %v", err)
	}
	if listed, _ := collectDomains(t, manager.WorkspaceDomains(ctx, actor, workspace.ID, credbound.PageRequest{})); len(listed) != 1 || listed[0].ConfirmedAt == nil {
		t.Fatalf("domain not confirmed after verification: %#v", listed)
	}
}

func TestDomainEnforcementCanonicalizesUnicodeDomain(t *testing.T) {
	f := newFixture(t, jitProvider("subject-idn", "user@example.com", true))
	ctx := context.Background()
	authn, workspace := f.bootstrap(t)
	actor := aal2(authn.UserID, f.now)
	const unicodeDomain = "café.example.com"
	asciiDomain, err := idna.Lookup.ToASCII(unicodeDomain)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := f.manager.CreateWorkspaceDomain(ctx, actor, workspace.ID, asciiDomain)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.ConfirmWorkspaceDomain(ctx, actor, issued.Domain.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.UpdateWorkspaceDomainPolicy(ctx, actor, issued.Domain.ID, credbound.WorkspaceDomainPolicyInput{
		EnforceSSO: true, SSOProviderConfigurationID: domainProviderA,
	}); err != nil {
		t.Fatal(err)
	}
	// Both the ASCII (punycode) form the domain was registered under and the
	// Unicode form an attacker might type are folded to the same name, so SSO
	// enforcement catches the Unicode homograph instead of letting it past.
	for _, address := range []string{"user@" + asciiDomain, "user@" + unicodeDomain} {
		if _, err := f.manager.AuthenticatePassword(ctx, address, "whatever password"); !errors.Is(err, credbound.ErrSSORequired) {
			t.Fatalf("enforcement for %q = %v", address, err)
		}
	}
}
