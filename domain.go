package credbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// canonicalDomainForLookup folds a domain to the ASCII (punycode), lowercase
// form domains are stored in, so a policy lookup catches an address written
// with the Unicode form of an enforced domain instead of silently missing it.
// A domain that cannot be canonicalized is returned lowercased unchanged; it
// then matches no stored ASCII domain, which is the fail-safe outcome.
func canonicalDomainForLookup(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if ascii, err := idna.Lookup.ToASCII(domain); err == nil {
		return ascii
	}
	return domain
}

// domainChallengePrefix frames the DNS TXT value proving domain control. The
// value is deliberately not a secret: the host publishes it in public DNS.
const domainChallengePrefix = "credbound-domain-verification="

// CreateWorkspaceDomain registers an email domain for the workspace in a
// pending state and returns the DNS challenge value the host publishes as a
// TXT record. Credbound performs no network I/O: the host proves control of
// the domain out of band and then calls ConfirmWorkspaceDomain. The domain
// name is normalized to lowercase and must be a registrable DNS name, unique
// across all workspaces (ErrConflict). It requires a DomainStore-capable
// store (ErrNotSupported otherwise), a fresh AAL2 step-up and workspace
// settings write, exactly like UpdateWorkspace. An unconfirmed domain has no
// effect on any flow.
func (m *Manager) CreateWorkspaceDomain(ctx context.Context, actor Authentication, workspaceID, domain string) (_ IssuedWorkspaceDomain, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.domain.create", started, err) }()
	if m.domainStore == nil {
		return IssuedWorkspaceDomain{}, ErrNotSupported
	}
	if err := m.authorizeWorkspaceMutation(ctx, actor, workspaceID, PermissionWorkspaceSettingsWrite, "workspace.domain.create"); err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	name, err := validWorkspaceDomainName(domain)
	if err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	id, err := m.newID()
	if err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	secret, err := randomBytes(m.random, 32)
	if err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	challenge := domainChallengePrefix + base64.RawURLEncoding.EncodeToString(secret)
	now := m.now()
	record := WorkspaceDomain{
		ID: id, WorkspaceID: workspaceID, Domain: name, Challenge: challenge,
		CreatedAt: now, UpdatedAt: now,
	}
	event, err := m.newAudit(ctx, actor.UserID, "workspace.domain.create", "workspace_domain", id, workspaceID, AuditSucceeded, "")
	if err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	meta, err := m.newEventMeta(EventWorkspaceDomainCreated, "workspace.domain.create", actor.UserID, workspaceID, event)
	if err != nil {
		return IssuedWorkspaceDomain{}, err
	}
	change := WorkspaceDomainChange{EventMeta: meta, Domain: record}
	commit := m.transactionalCommit(event, "workspace.domain.create", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceDomainChange(ctx, tx, change)
	})
	if err := m.domainStore.CreateWorkspaceDomain(ctx, record, commit); err != nil {
		return IssuedWorkspaceDomain{}, m.mapStoreError(ctx, "workspace.domain.create", err)
	}
	created := WorkspaceDomainEvent{EventMeta: meta, Domain: record}
	m.events.emit(ctx, EventWorkspaceDomainCreated, func(listener EventListener) error { return listener.OnWorkspaceDomainCreated(ctx, created) })
	return IssuedWorkspaceDomain{Domain: record, Challenge: challenge}, nil
}

// ConfirmWorkspaceDomain marks the pending domain verified. When a
// Config.DomainVerifier is registered it proves control here — resolving the
// challenge against the domain's DNS — and fails with ErrDomainVerification
// when the challenge is not published; without one, calling it is the actor's
// assertion that DNS verification completed and Credbound never queries DNS
// itself. It requires a fresh AAL2 step-up and workspace settings write in the
// owning workspace, and fails with ErrConflict when the domain was already
// confirmed. Only from this point on does the domain's policy apply.
func (m *Manager) ConfirmWorkspaceDomain(ctx context.Context, actor Authentication, domainID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.domain.confirm", started, err) }()
	if m.domainStore == nil {
		return ErrNotSupported
	}
	domain, err := m.authorizedWorkspaceDomain(ctx, actor, domainID, "workspace.domain.confirm")
	if err != nil {
		return err
	}
	if domain.ConfirmedAt != nil {
		return fmt.Errorf("%w: the domain is already confirmed", ErrConflict)
	}
	// When a verifier is registered, ownership is proven here against the
	// challenge minted at creation rather than trusted on the actor's word: a
	// confirmed domain governs SSO enforcement and JIT provisioning for every
	// address on it, instance-wide.
	if m.domainVerifier != nil {
		if verifyErr := m.domainVerifier.VerifyDomain(ctx, domain.Domain, domain.Challenge); verifyErr != nil {
			return fmt.Errorf("%w: %v", ErrDomainVerification, verifyErr)
		}
	}
	now := m.now()
	domain.ConfirmedAt, domain.UpdatedAt = cloneTime(&now), now
	event, err := m.newAudit(ctx, actor.UserID, "workspace.domain.confirm", "workspace_domain", domain.ID, domain.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventWorkspaceDomainConfirmed, "workspace.domain.confirm", actor.UserID, domain.WorkspaceID, event)
	if err != nil {
		return err
	}
	change := WorkspaceDomainChange{EventMeta: meta, Domain: domain}
	commit := m.transactionalCommit(event, "workspace.domain.confirm", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceDomainChange(ctx, tx, change)
	})
	if err := m.domainStore.ConfirmWorkspaceDomain(ctx, domain.ID, now, commit); err != nil {
		return m.mapStoreError(ctx, "workspace.domain.confirm", err)
	}
	confirmed := WorkspaceDomainEvent{EventMeta: meta, Domain: domain}
	m.events.emit(ctx, EventWorkspaceDomainConfirmed, func(listener EventListener) error { return listener.OnWorkspaceDomainConfirmed(ctx, confirmed) })
	return nil
}

// UpdateWorkspaceDomainPolicy replaces the policy of a confirmed domain: the
// auto-join flag with its target role, the SSO provider configuration the
// domain trusts, and the SSO enforcement flag. An unconfirmed domain fails
// with ErrConflict. A zero AutoJoinRole means member and the role must exist
// in the workspace role catalog; when AutoJoin or EnforceSSO is set the
// provider configuration must be registered with the Manager. It requires a
// fresh AAL2 step-up and workspace settings write in the owning workspace.
func (m *Manager) UpdateWorkspaceDomainPolicy(ctx context.Context, actor Authentication, domainID string, input WorkspaceDomainPolicyInput) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.domain.policy_update", started, err) }()
	if m.domainStore == nil {
		return ErrNotSupported
	}
	domain, err := m.authorizedWorkspaceDomain(ctx, actor, domainID, "workspace.domain.policy_update")
	if err != nil {
		return err
	}
	if domain.ConfirmedAt == nil {
		return fmt.Errorf("%w: only a confirmed domain carries policy", ErrConflict)
	}
	if input.AutoJoinRole == "" {
		input.AutoJoinRole = RoleMember
	}
	role, err := m.workspaceRoles.normalize(input.AutoJoinRole)
	if err != nil {
		return err
	}
	input.AutoJoinRole = role
	input.SSOProviderConfigurationID = strings.TrimSpace(input.SSOProviderConfigurationID)
	if input.AutoJoin || input.EnforceSSO || input.SSOProviderConfigurationID != "" {
		if _, registered := m.ssoProviders[input.SSOProviderConfigurationID]; !registered {
			return &ValidationError{Field: "sso_provider_configuration_id", Rule: "unknown", Message: "the SSO provider configuration is not registered"}
		}
	}
	now := m.now()
	domain.AutoJoin, domain.AutoJoinRole = input.AutoJoin, input.AutoJoinRole
	domain.SSOProviderConfigurationID, domain.EnforceSSO = input.SSOProviderConfigurationID, input.EnforceSSO
	domain.UpdatedAt = now
	event, err := m.newAudit(ctx, actor.UserID, "workspace.domain.policy_update", "workspace_domain", domain.ID, domain.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventWorkspaceDomainPolicyUpdated, "workspace.domain.policy_update", actor.UserID, domain.WorkspaceID, event)
	if err != nil {
		return err
	}
	change := WorkspaceDomainChange{EventMeta: meta, Domain: domain}
	commit := m.transactionalCommit(event, "workspace.domain.policy_update", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceDomainChange(ctx, tx, change)
	})
	if err := m.domainStore.UpdateWorkspaceDomainPolicy(ctx, domain.ID, input, now, commit); err != nil {
		return m.mapStoreError(ctx, "workspace.domain.policy_update", err)
	}
	updated := WorkspaceDomainEvent{EventMeta: meta, Domain: domain}
	m.events.emit(ctx, EventWorkspaceDomainPolicyUpdated, func(listener EventListener) error { return listener.OnWorkspaceDomainPolicyUpdated(ctx, updated) })
	return nil
}

// RemoveWorkspaceDomain deletes the domain and its policy, atomically with
// the audit event; addresses under it immediately authenticate like any
// other. It requires a fresh AAL2 step-up and workspace settings write in
// the owning workspace.
func (m *Manager) RemoveWorkspaceDomain(ctx context.Context, actor Authentication, domainID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "workspace.domain.remove", started, err) }()
	if m.domainStore == nil {
		return ErrNotSupported
	}
	domain, err := m.authorizedWorkspaceDomain(ctx, actor, domainID, "workspace.domain.remove")
	if err != nil {
		return err
	}
	event, err := m.newAudit(ctx, actor.UserID, "workspace.domain.remove", "workspace_domain", domain.ID, domain.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventWorkspaceDomainRemoved, "workspace.domain.remove", actor.UserID, domain.WorkspaceID, event)
	if err != nil {
		return err
	}
	change := WorkspaceDomainChange{EventMeta: meta, Domain: domain, Removed: true}
	commit := m.transactionalCommit(event, "workspace.domain.remove", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyWorkspaceDomainChange(ctx, tx, change)
	})
	if err := m.domainStore.DeleteWorkspaceDomain(ctx, domain.ID, commit); err != nil {
		return m.mapStoreError(ctx, "workspace.domain.remove", err)
	}
	removed := WorkspaceDomainEvent{EventMeta: meta, Domain: domain}
	m.events.emit(ctx, EventWorkspaceDomainRemoved, func(listener EventListener) error { return listener.OnWorkspaceDomainRemoved(ctx, removed) })
	return nil
}

// WorkspaceDomains streams the workspace's domains with their confirmation
// state and policy. The listing requires an active membership holding
// workspace access, like the other tenant read operations; the challenge is
// included because it is published in public DNS and is not a secret.
func (m *Manager) WorkspaceDomains(ctx context.Context, actor Authentication, workspaceID string, page PageRequest) iter.Seq2[PageEvent[WorkspaceDomain], error] {
	if m.domainStore == nil {
		return errorSeq[PageEvent[WorkspaceDomain]](ErrNotSupported)
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceAccess); err != nil {
		return errorSeq[PageEvent[WorkspaceDomain]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[WorkspaceDomain]](err)
	}
	return m.domainStore.WorkspaceDomains(ctx, workspaceID, page)
}

// authorizedWorkspaceDomain resolves a domain identifier and authorizes the
// actor for a mutation of its workspace: a fresh AAL2 step-up plus workspace
// settings write on the owning workspace, mirroring UpdateWorkspace. The
// step-up gate runs before the lookup so anonymous or stale contexts cannot
// probe domain identifiers.
func (m *Manager) authorizedWorkspaceDomain(ctx context.Context, actor Authentication, domainID, operation string) (WorkspaceDomain, error) {
	if err := m.requireStepUp(ctx, actor, operation); err != nil {
		return WorkspaceDomain{}, err
	}
	if !validUUIDv7(domainID) {
		return WorkspaceDomain{}, fmt.Errorf("%w: invalid workspace domain id", ErrInvalidInput)
	}
	domain, err := m.domainStore.WorkspaceDomainByID(ctx, domainID)
	if err != nil {
		return WorkspaceDomain{}, err
	}
	if err := m.authorizeWorkspaceMutation(ctx, actor, domain.WorkspaceID, PermissionWorkspaceSettingsWrite, operation); err != nil {
		return WorkspaceDomain{}, err
	}
	return domain, nil
}

// validWorkspaceDomainName normalizes and validates a registrable DNS domain
// name: lowercase, at most 253 characters, at least two labels of at most 63
// characters from [a-z0-9-] without leading or trailing hyphens, and not an
// IP address literal.
func validWorkspaceDomainName(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", &ValidationError{Field: "domain", Rule: "required", Message: "domain is required"}
	}
	invalid := &ValidationError{Field: "domain", Rule: "format", Message: "domain must be a registrable DNS name"}
	if len(normalized) > 253 || !strings.Contains(normalized, ".") || net.ParseIP(normalized) != nil {
		return "", invalid
	}
	for label := range strings.SplitSeq(normalized, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", invalid
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", invalid
			}
		}
	}
	// Reject a bare public suffix (an eTLD such as "com" or "co.uk"): it is not
	// a registrable domain, so no single workspace may claim it. A registrable
	// domain or any subdomain of one is accepted.
	if suffix, _ := publicsuffix.PublicSuffix(normalized); normalized == suffix {
		return "", &ValidationError{Field: "domain", Rule: "format", Message: "domain must not be a public suffix"}
	}
	return normalized, nil
}

// domainRequiresSSO enforces SSO-006 at the top of the password, reset,
// magic-link and email-OTP flows, before any user lookup or cryptographic
// work: when the normalized address falls under a confirmed domain whose
// policy enforces SSO, the flow is rejected with ErrSSORequired. The outcome
// depends only on the domain — never on whether an account exists — so it
// introduces no enumeration oracle (per ADR-017). The rejection is audited
// under the flow's action with reason "sso_required" and an empty actor,
// since no account was resolved. Without a DomainStore the check is free and
// always passes; infrastructure errors propagate.
// domainRequiresSSO matches the exact registered domain of the address:
// user@sub.corp.example is NOT covered by a policy on corp.example, by
// design — over-matching would let a subdomain identity join or be forced
// into the parent workspace. Hosts that need subdomain coverage register
// each subdomain explicitly. Domains are stored in their ASCII form and the
// address domain is folded to the same ASCII (punycode) form before the
// lookup, so an address written with the Unicode form of an enforced domain
// is caught rather than slipping past enforcement.
func (m *Manager) domainRequiresSSO(ctx context.Context, email, action string) error {
	if m.domainStore == nil {
		return nil
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return nil
	}
	domain, err := m.domainStore.ConfirmedWorkspaceDomainByName(ctx, canonicalDomainForLookup(email[at+1:]))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if !domain.EnforceSSO {
		return nil
	}
	if auditErr := m.appendAuthenticationAudit(ctx, "", action, AuditFailed, "sso_required"); auditErr != nil {
		return auditErr
	}
	return ErrSSORequired
}
