package credbound

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"strings"
	"time"
)

const (
	ssoLogin  = "login"
	ssoLink   = "link"
	ssoStepUp = "step_up"
)

type ssoContinuation struct {
	// ID is the single-use ceremony identity consumed by the success
	// commit; continuations sealed before ceremony ids existed carry none
	// and stay bounded by the TTL alone.
	ID                      UUID      `json:"id,omitempty"`
	ProviderConfigurationID UUID      `json:"provider_configuration_id"`
	Operation               string    `json:"operation"`
	UserID                  UUID      `json:"user_id,omitempty"`
	ExpiresAt               time.Time `json:"expires_at"`
	Session                 []byte    `json:"session"`
}

// consumption reports the single-use ceremony this continuation carries,
// or nil for a continuation sealed before ceremony ids existed, which stays
// bounded by its TTL alone.
func (c ssoContinuation) consumption() *CeremonyConsumption {
	if c.ID == (UUID{}) {
		return nil
	}
	return &CeremonyConsumption{ID: c.ID, ExpiresAt: c.ExpiresAt}
}

// BeginSSO starts a sign-in ceremony with a registered provider and returns
// the redirect URL with a sealed continuation for FinishSSO. No actor is
// required; an unregistered configuration fails with ErrNotFound. Sign-in
// only succeeds for an identity previously linked with BeginSSOLink —
// Credbound never matches accounts by IdP email.
func (m *Manager) BeginSSO(ctx context.Context, providerConfigurationID UUID) (SSOChallenge, error) {
	return m.beginSSO(ctx, Authentication{}, providerConfigurationID, ssoLogin)
}

// BeginSSOLink starts a ceremony that links the provider identity to the
// actor's existing account when finished. It requires a recent interactive
// authentication, per the explicit-linking policy.
func (m *Manager) BeginSSOLink(ctx context.Context, actor Authentication, providerConfigurationID UUID) (SSOChallenge, error) {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return SSOChallenge{}, err
	}
	return m.beginSSO(ctx, actor, providerConfigurationID, ssoLink)
}

// BeginSSOStepUp starts a step-up ceremony for the actor: the provider is
// asked to force reauthentication and its own MFA, and the finished ceremony
// must resolve to an identity already linked to this actor. It requires a
// recent interactive authentication.
func (m *Manager) BeginSSOStepUp(ctx context.Context, actor Authentication, providerConfigurationID UUID) (SSOChallenge, error) {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return SSOChallenge{}, err
	}
	return m.beginSSO(ctx, actor, providerConfigurationID, ssoStepUp)
}

func (m *Manager) beginSSO(ctx context.Context, actor Authentication, providerConfigurationID UUID, operation string) (_ SSOChallenge, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.sso.begin", started, err) }()
	provider, ok := m.ssoProviders[providerConfigurationID]
	if !ok {
		return SSOChallenge{}, ErrNotFound
	}
	providerChallenge, err := provider.Begin(ctx, SSORequest{ForceReauthentication: operation == ssoStepUp})
	if err != nil {
		return SSOChallenge{}, fmt.Errorf("begin SSO: %w", err)
	}
	if strings.TrimSpace(providerChallenge.RedirectURL) == "" || len(providerChallenge.Session) == 0 {
		return SSOChallenge{}, fmt.Errorf("%w: SSO provider returned an incomplete challenge", ErrInvalidInput)
	}
	ceremonyID, err := m.newID()
	if err != nil {
		return SSOChallenge{}, err
	}
	state := ssoContinuation{
		ID: ceremonyID, ProviderConfigurationID: providerConfigurationID, Operation: operation,
		UserID: actor.UserID, ExpiresAt: m.now().Add(m.ceremonyTTL), Session: providerChallenge.Session,
	}
	continuation, err := m.encodeSSOContinuation(state)
	if err != nil {
		return SSOChallenge{}, err
	}
	challenge := SSOChallenge{RedirectURL: providerChallenge.RedirectURL, Continuation: continuation}
	if meta, metaErr := m.newEventMeta(EventSSOChallengeIssued, "auth.sso.begin", actor.UserID, UUID{}, AuditEvent{}); metaErr == nil {
		issued := SSOChallengeIssuedEvent{
			EventMeta: meta, ProviderConfigurationID: providerConfigurationID,
			ProviderKind: provider.Kind(), Purpose: operation,
		}
		m.events.emit(ctx, EventSSOChallengeIssued, func(listener EventListener) error { return listener.OnSSOChallengeIssued(ctx, issued) })
	}
	return challenge, nil
}

// FinishSSO completes any SSO ceremony (sign-in, link or step-up) by
// validating the provider response against the sealed continuation. The
// authentication is AAL2 only when the provider carries a Config.SSOAssurance
// policy the asserted context satisfies (or that trusts the provider
// unverified); otherwise it is AAL1, because SSO never mints AAL2 on the
// IdP's unverified word. Link ceremonies persist the
// new identity atomically with the audit event; sign-in and step-up resolve
// the stable issuer/subject pair and update its last use. Failed or
// mismatched ceremonies return ErrInvalidCredentials, stale continuations
// ErrExpired.
//
// On a DomainStore-capable store, a sign-in whose identity is unknown may
// JIT-provision an account: when the IdP-verified email belongs to a
// confirmed auto-join workspace domain that trusts this provider
// configuration and no existing account owns the address, one transaction
// creates a passwordless user, its verified primary email, the configured
// membership, and the identity link. An address owned by an existing account
// is never auto-linked and the sign-in fails as an unknown identity.
func (m *Manager) FinishSSO(ctx context.Context, continuation string, response []byte) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.sso.finish", started, err) }()
	state, err := m.decodeSSOContinuation(continuation)
	if err != nil {
		return Authentication{}, err
	}
	provider, ok := m.ssoProviders[state.ProviderConfigurationID]
	if !ok {
		return Authentication{}, ErrInvalidCredentials
	}
	claims, err := provider.Finish(ctx, state.Session, response)
	if err != nil {
		if state.UserID != (UUID{}) {
			audit, auditErr := m.recordAuthenticationAudit(ctx, state.UserID, "auth.sso", AuditFailed, "invalid_credentials")
			if auditErr != nil {
				return Authentication{}, auditErr
			}
			m.emitAuthenticationFailed(ctx, "auth.sso.finish", audit, MethodSSO, state.UserID, "invalid_credentials")
		}
		return Authentication{}, ErrInvalidCredentials
	}
	claims.Issuer, claims.Subject = strings.TrimSpace(claims.Issuer), strings.TrimSpace(claims.Subject)
	if claims.Issuer == "" || claims.Subject == "" || len(claims.Issuer) > 500 || len(claims.Subject) > 500 {
		return Authentication{}, ErrInvalidCredentials
	}
	// A registered assurance policy is the only thing that lifts an SSO
	// sign-in to AAL2: without one the provider's word is unverified and the
	// authentication stays AAL1, so it can neither satisfy a RequireMFA
	// workspace nor a step-up. A policy that is present but unsatisfied fails
	// closed with ErrStepUpRequired so the host can send the user back to the
	// IdP for its second factor.
	level := AAL1
	if policy, constrained := m.ssoAssurance[state.ProviderConfigurationID]; constrained {
		if !policy.satisfiedBy(claims) {
			if state.UserID != (UUID{}) {
				audit, auditErr := m.recordAuthenticationAudit(ctx, state.UserID, "auth.sso", AuditFailed, "assurance_policy")
				if auditErr != nil {
					return Authentication{}, auditErr
				}
				m.emitAuthenticationFailed(ctx, "auth.sso.finish", audit, MethodSSO, state.UserID, "assurance_policy")
			}
			return Authentication{}, ErrStepUpRequired
		}
		level = AAL2
	}
	if claims.Email != "" {
		normalizedEmail, emailErr := validEmail(claims.Email)
		if emailErr != nil {
			return Authentication{}, ErrInvalidCredentials
		}
		claims.Email = normalizedEmail
	}
	if state.Operation == ssoLink {
		return m.finishSSOLink(ctx, provider, state, claims, level)
	}
	identity, lookupErr := m.store.SSOIdentity(ctx, state.ProviderConfigurationID, claims.Issuer, claims.Subject)
	if lookupErr != nil {
		if !errors.Is(lookupErr, ErrNotFound) {
			return Authentication{}, lookupErr
		}
		// SSO-005: an unknown identity on the sign-in path may be provisioned
		// just in time by a confirmed auto-join domain. Step-up ceremonies
		// must resolve to an already linked identity and keep failing here.
		if state.Operation == ssoLogin {
			return m.finishSSOJIT(ctx, provider, state, claims, level)
		}
		return Authentication{}, ErrInvalidCredentials
	}
	if state.Operation == ssoStepUp && identity.UserID != state.UserID {
		return Authentication{}, ErrInvalidCredentials
	}
	user, err := m.store.UserByID(ctx, identity.UserID)
	if err != nil || user.Disabled {
		return Authentication{}, ErrInvalidCredentials
	}
	now := m.now()
	event, err := m.newAudit(ctx, user.ID, "auth.sso", "sso_identity", identity.ID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	if err := m.store.TouchSSO(ctx, user.ID, identity.ID, now, Commit{Audit: event, Ceremony: state.consumption()}); err != nil {
		if errors.Is(err, ErrConflict) {
			// The ceremony was already consumed: a replayed response can
			// never commit twice, and answers like any invalid credential.
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, m.mapStoreError(ctx, "auth.sso.finish", err)
	}
	authentication := Authentication{UserID: user.ID, Method: MethodSSO, Level: level, AuthenticatedAt: now}
	if meta, metaErr := m.newEventMeta(EventSSOAuthenticated, "auth.sso.finish", user.ID, UUID{}, event); metaErr == nil {
		authenticated := SSOAuthenticatedEvent{EventMeta: meta, IdentityID: identity.ID, Authentication: authentication}
		m.events.emit(ctx, EventSSOAuthenticated, func(listener EventListener) error { return listener.OnSSOAuthenticated(ctx, authenticated) })
	}
	m.emitAuthenticationSucceeded(ctx, "auth.sso.finish", event, authentication)
	return authentication, nil
}

// finishSSOJIT resolves an unknown sign-in identity through domain-based JIT
// provisioning (SSO-005): when the store has the domain capability, the IdP
// asserted a verified email whose domain is a confirmed auto-join domain
// trusting exactly the provider configuration completing this ceremony, and
// no account owns the address, one store transaction creates a passwordless
// user with LastSeenAt set, its verified primary email, the configured
// membership (ProvisioningSource "jit:<domainID>") and the SSO identity
// link. The ApplyUserCreate and ApplySSOLink hooks run inside that
// transaction, and the success emits user.created, sso.linked,
// sso.jit_provisioned and authentication.succeeded with the same "auth.sso"
// audit as a normal SSO login. Any account already owning the address — the
// SSO-002 no-auto-link rule — and every other refusal reproduce today's
// unknown-identity failure verbatim: ErrInvalidCredentials.
func (m *Manager) finishSSOJIT(ctx context.Context, provider SSOProvider, state ssoContinuation, claims SSOClaims, level AssuranceLevel) (Authentication, error) {
	if m.domainStore == nil || !claims.EmailVerified || claims.Email == "" {
		return Authentication{}, ErrInvalidCredentials
	}
	at := strings.LastIndexByte(claims.Email, '@')
	if at < 0 || at == len(claims.Email)-1 {
		return Authentication{}, ErrInvalidCredentials
	}
	domain, err := m.domainStore.ConfirmedWorkspaceDomainByName(ctx, claims.Email[at+1:])
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, err
	}
	if !domain.AutoJoin || domain.SSOProviderConfigurationID != state.ProviderConfigurationID {
		return Authentication{}, ErrInvalidCredentials
	}
	// A disabled workspace accepts no new members (TENANT-002): JIT refuses
	// exactly like any other ineligible identity.
	workspace, err := m.store.WorkspaceByID(ctx, domain.WorkspaceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, err
	}
	if workspace.DisabledAt != nil {
		return Authentication{}, ErrInvalidCredentials
	}
	if _, ownerErr := m.store.UserByEmail(ctx, claims.Email); ownerErr == nil {
		// SSO-002 holds: an existing account is never auto-linked and the
		// login fails exactly like any unknown identity.
		return Authentication{}, ErrInvalidCredentials
	} else if !errors.Is(ownerErr, ErrNotFound) {
		return Authentication{}, ownerErr
	}
	userID, err := m.newID()
	if err != nil {
		return Authentication{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return Authentication{}, err
	}
	identityID, err := m.newID()
	if err != nil {
		return Authentication{}, err
	}
	now := m.now()
	role := domain.AutoJoinRole
	if role == "" {
		role = RoleMember
	}
	user := User{ID: userID, Email: claims.Email, DisplayName: claims.Email, LastSeenAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	primaryEmail := EmailAddress{ID: emailID, UserID: userID, Address: claims.Email, Primary: true, VerifiedAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	membership := Membership{
		WorkspaceID: domain.WorkspaceID, UserID: userID, Role: role, Status: MembershipActive,
		ProvisioningSource: "jit:" + domain.ID.String(), CreatedAt: now, UpdatedAt: now,
	}
	identity := SSOIdentity{
		ID: identityID, UserID: userID, ProviderConfigurationID: state.ProviderConfigurationID,
		ProviderKind: provider.Kind(), Issuer: claims.Issuer, Subject: claims.Subject,
		Email: claims.Email, CreatedAt: now, LastUsedAt: cloneTime(&now),
	}
	event, err := m.newAudit(ctx, userID, "auth.sso", "sso_identity", identityID.String(), domain.WorkspaceID, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	userMeta, err := m.newEventMeta(EventUserCreated, "auth.sso.finish", userID, domain.WorkspaceID, event)
	if err != nil {
		return Authentication{}, err
	}
	linkMeta, err := m.newEventMeta(EventSSOLinked, "auth.sso.finish", userID, domain.WorkspaceID, event)
	if err != nil {
		return Authentication{}, err
	}
	jitMeta, err := m.newEventMeta(EventSSOJITProvisioned, "auth.sso.finish", userID, domain.WorkspaceID, event)
	if err != nil {
		return Authentication{}, err
	}
	userChange := UserCreateChange{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	linkChange := SSOLink{EventMeta: linkMeta, Identity: identity}
	commit := Commit{Audit: event, Ceremony: state.consumption(), Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "user.create", func(hook TransactionHook) error {
			return hook.ApplyUserCreate(ctx, tx, userChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "sso.link", func(hook TransactionHook) error {
			return hook.ApplySSOLink(ctx, tx, linkChange)
		})
	}}
	if err := m.domainStore.JITProvisionSSOUser(ctx, user, primaryEmail, membership, identity, now, commit); err != nil {
		if errors.Is(err, ErrConflict) {
			// A concurrent registration claimed the address or identity
			// between the lookup and the commit: preserve the unknown-identity
			// failure.
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, m.mapStoreError(ctx, "auth.sso.finish", err)
	}
	userEvent := UserCreatedEvent{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	m.events.emit(ctx, EventUserCreated, func(listener EventListener) error { return listener.OnUserCreated(ctx, userEvent) })
	linkedEvent := SSOLinkedEvent{EventMeta: linkMeta, Identity: identity}
	m.events.emit(ctx, EventSSOLinked, func(listener EventListener) error { return listener.OnSSOLinked(ctx, linkedEvent) })
	jitEvent := SSOJITProvisionedEvent{EventMeta: jitMeta, User: user, Email: primaryEmail, Membership: membership, Identity: identity, DomainID: domain.ID}
	m.events.emit(ctx, EventSSOJITProvisioned, func(listener EventListener) error { return listener.OnSSOJITProvisioned(ctx, jitEvent) })
	authentication := Authentication{UserID: userID, Method: MethodSSO, Level: level, AuthenticatedAt: now}
	m.emitAuthenticationSucceeded(ctx, "auth.sso.finish", event, authentication)
	return authentication, nil
}

func (m *Manager) finishSSOLink(ctx context.Context, provider SSOProvider, state ssoContinuation, claims SSOClaims, level AssuranceLevel) (Authentication, error) {
	id, err := m.newID()
	if err != nil {
		return Authentication{}, err
	}
	now := m.now()
	identity := SSOIdentity{
		ID: id, UserID: state.UserID, ProviderConfigurationID: state.ProviderConfigurationID,
		ProviderKind: provider.Kind(), Issuer: claims.Issuer, Subject: claims.Subject,
		Email: claims.Email, CreatedAt: now, LastUsedAt: cloneTime(&now),
	}
	event, err := m.newAudit(ctx, state.UserID, "sso.link", "sso_identity", id.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	meta, err := m.newEventMeta(EventSSOLinked, "auth.sso.finish", state.UserID, UUID{}, event)
	if err != nil {
		return Authentication{}, err
	}
	change := SSOLink{EventMeta: meta, Identity: identity}
	commit := m.transactionalCommit(event, "sso.link", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySSOLink(ctx, tx, change)
	})
	commit.Ceremony = state.consumption()
	if err := m.store.LinkSSO(ctx, identity, commit); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.sso.link", err)
	}
	linked := SSOLinkedEvent{EventMeta: meta, Identity: identity}
	m.events.emit(ctx, EventSSOLinked, func(listener EventListener) error { return listener.OnSSOLinked(ctx, linked) })
	return Authentication{UserID: state.UserID, Method: MethodSSO, Level: level, AuthenticatedAt: now}, nil
}

// UnlinkSSO removes one of the actor's linked external identities,
// atomically with the audit event. It requires a fresh AAL2 step-up, and
// fails with ErrConflict when the identity is the actor's last remaining
// authentication method (no password, no passkey, no other SSO identity), so
// a JIT-provisioned passwordless member cannot lock themselves out.
func (m *Manager) UnlinkSSO(ctx context.Context, actor Authentication, identityID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.sso.unlink", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.sso.unlink"); err != nil {
		return err
	}
	if !validUUIDv7(identityID) {
		return fmt.Errorf("%w: invalid SSO identity id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "sso.unlink", "sso_identity", identityID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSSOUnlinked, "auth.sso.unlink", actor.UserID, UUID{}, event)
	if err != nil {
		return err
	}
	change := SSOUnlink{EventMeta: meta, UserID: actor.UserID, IdentityID: identityID}
	commit := m.transactionalCommit(event, "sso.unlink", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySSOUnlink(ctx, tx, change)
	})
	if err := m.store.UnlinkSSO(ctx, actor.UserID, identityID, commit); err != nil {
		return m.mapStoreError(ctx, "auth.sso.unlink", err)
	}
	unlinked := SSOUnlinkedEvent{EventMeta: meta, UserID: actor.UserID, IdentityID: identityID}
	m.events.emit(ctx, EventSSOUnlinked, func(listener EventListener) error { return listener.OnSSOUnlinked(ctx, unlinked) })
	return nil
}

// SSOIdentities streams a user's linked external identities with their
// latest uses. An empty userID means the actor, which requires a recent
// interactive authentication; reading another user requires admin users
// read — the same scoping as Sessions, Emails and Passkeys.
func (m *Manager) SSOIdentities(ctx context.Context, actor Authentication, userID UUID, page PageRequest) iter.Seq2[PageEvent[SSOIdentity], error] {
	if actor.UserID == (UUID{}) {
		return errorSeq[PageEvent[SSOIdentity]](ErrUnauthorized)
	}
	if userID == (UUID{}) {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return errorSeq[PageEvent[SSOIdentity]](err)
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return errorSeq[PageEvent[SSOIdentity]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[SSOIdentity]](err)
	}
	return m.store.SSOIdentities(ctx, userID, page)
}

func (m *Manager) encodeSSOContinuation(state ssoContinuation) (string, error) {
	payload, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	sealed, err := m.seal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) decodeSSOContinuation(raw string) (ssoContinuation, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	payload, err := m.open(sealed)
	if err != nil {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	var state ssoContinuation
	if err := json.Unmarshal(payload, &state); err != nil || !validUUIDv7(state.ProviderConfigurationID) || len(state.Session) == 0 {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	if state.Operation != ssoLogin && state.Operation != ssoLink && state.Operation != ssoStepUp {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	if (state.Operation == ssoLink || state.Operation == ssoStepUp) && state.UserID == (UUID{}) {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	if !m.now().Before(state.ExpiresAt) {
		return ssoContinuation{}, ErrExpired
	}
	return state, nil
}
