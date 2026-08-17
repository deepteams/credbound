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
	ProviderConfigurationID string    `json:"provider_configuration_id"`
	Operation               string    `json:"operation"`
	UserID                  string    `json:"user_id,omitempty"`
	ExpiresAt               time.Time `json:"expires_at"`
	Session                 []byte    `json:"session"`
}

// BeginSSO starts a sign-in ceremony with a registered provider and returns
// the redirect URL with a sealed continuation for FinishSSO. No actor is
// required; an unregistered configuration fails with ErrNotFound. Sign-in
// only succeeds for an identity previously linked with BeginSSOLink —
// Credbound never matches accounts by IdP email.
func (m *Manager) BeginSSO(ctx context.Context, providerConfigurationID string) (SSOChallenge, error) {
	return m.beginSSO(ctx, Authentication{}, providerConfigurationID, ssoLogin)
}

// BeginSSOLink starts a ceremony that links the provider identity to the
// actor's existing account when finished. It requires a recent interactive
// authentication, per the explicit-linking policy.
func (m *Manager) BeginSSOLink(ctx context.Context, actor Authentication, providerConfigurationID string) (SSOChallenge, error) {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return SSOChallenge{}, err
	}
	return m.beginSSO(ctx, actor, providerConfigurationID, ssoLink)
}

// BeginSSOStepUp starts a step-up ceremony for the actor: the provider is
// asked to force reauthentication and its own MFA, and the finished ceremony
// must resolve to an identity already linked to this actor. It requires a
// recent interactive authentication.
func (m *Manager) BeginSSOStepUp(ctx context.Context, actor Authentication, providerConfigurationID string) (SSOChallenge, error) {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return SSOChallenge{}, err
	}
	return m.beginSSO(ctx, actor, providerConfigurationID, ssoStepUp)
}

func (m *Manager) beginSSO(ctx context.Context, actor Authentication, providerConfigurationID, operation string) (_ SSOChallenge, err error) {
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
	state := ssoContinuation{
		ProviderConfigurationID: providerConfigurationID, Operation: operation,
		UserID: actor.UserID, ExpiresAt: m.now().Add(m.ceremonyTTL), Session: providerChallenge.Session,
	}
	continuation, err := m.encodeSSOContinuation(state)
	if err != nil {
		return SSOChallenge{}, err
	}
	challenge := SSOChallenge{RedirectURL: providerChallenge.RedirectURL, Continuation: continuation}
	if meta, metaErr := m.newEventMeta(EventSSOChallengeIssued, "auth.sso.begin", actor.UserID, "", AuditEvent{}); metaErr == nil {
		issued := SSOChallengeIssuedEvent{
			EventMeta: meta, ProviderConfigurationID: providerConfigurationID,
			ProviderKind: provider.Kind(), Purpose: operation,
		}
		m.events.emit(ctx, EventSSOChallengeIssued, func(listener EventListener) error { return listener.OnSSOChallengeIssued(ctx, issued) })
	}
	return challenge, nil
}

// FinishSSO completes any SSO ceremony (sign-in, link or step-up) by
// validating the provider response against the sealed continuation, and
// returns an AAL2 interactive authentication. Link ceremonies persist the
// new identity atomically with the audit event; sign-in and step-up resolve
// the stable issuer/subject pair and update its last use. Failed or
// mismatched ceremonies return ErrInvalidCredentials, stale continuations
// ErrExpired.
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
		if state.UserID != "" {
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
	if claims.Email != "" {
		normalizedEmail, emailErr := validEmail(claims.Email)
		if emailErr != nil {
			return Authentication{}, ErrInvalidCredentials
		}
		claims.Email = normalizedEmail
	}
	if state.Operation == ssoLink {
		return m.finishSSOLink(ctx, provider, state, claims)
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
			return m.finishSSOJIT(ctx, provider, state, claims)
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
	event, err := m.newAudit(ctx, user.ID, "auth.sso", "sso_identity", identity.ID, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	if err := m.store.TouchSSO(ctx, user.ID, identity.ID, now, Commit{Audit: event}); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.sso.finish", err)
	}
	authentication := Authentication{UserID: user.ID, Method: MethodSSO, Level: AAL2, AuthenticatedAt: now}
	if meta, metaErr := m.newEventMeta(EventSSOAuthenticated, "auth.sso.finish", user.ID, "", event); metaErr == nil {
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
func (m *Manager) finishSSOJIT(ctx context.Context, provider SSOProvider, state ssoContinuation, claims SSOClaims) (Authentication, error) {
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
		ProvisioningSource: "jit:" + domain.ID, CreatedAt: now, UpdatedAt: now,
	}
	identity := SSOIdentity{
		ID: identityID, UserID: userID, ProviderConfigurationID: state.ProviderConfigurationID,
		ProviderKind: provider.Kind(), Issuer: claims.Issuer, Subject: claims.Subject,
		Email: claims.Email, CreatedAt: now, LastUsedAt: cloneTime(&now),
	}
	event, err := m.newAudit(ctx, userID, "auth.sso", "sso_identity", identityID, domain.WorkspaceID, AuditSucceeded, "")
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
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
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
	authentication := Authentication{UserID: userID, Method: MethodSSO, Level: AAL2, AuthenticatedAt: now}
	m.emitAuthenticationSucceeded(ctx, "auth.sso.finish", event, authentication)
	return authentication, nil
}

func (m *Manager) finishSSOLink(ctx context.Context, provider SSOProvider, state ssoContinuation, claims SSOClaims) (Authentication, error) {
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
	event, err := m.newAudit(ctx, state.UserID, "sso.link", "sso_identity", id, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	meta, err := m.newEventMeta(EventSSOLinked, "auth.sso.finish", state.UserID, "", event)
	if err != nil {
		return Authentication{}, err
	}
	change := SSOLink{EventMeta: meta, Identity: identity}
	commit := m.transactionalCommit(event, "sso.link", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplySSOLink(ctx, tx, change)
	})
	if err := m.store.LinkSSO(ctx, identity, commit); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.sso.link", err)
	}
	linked := SSOLinkedEvent{EventMeta: meta, Identity: identity}
	m.events.emit(ctx, EventSSOLinked, func(listener EventListener) error { return listener.OnSSOLinked(ctx, linked) })
	return Authentication{UserID: state.UserID, Method: MethodSSO, Level: AAL2, AuthenticatedAt: now}, nil
}

// UnlinkSSO removes one of the actor's linked external identities,
// atomically with the audit event. It requires a fresh AAL2 step-up.
func (m *Manager) UnlinkSSO(ctx context.Context, actor Authentication, identityID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.sso.unlink", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.sso.unlink"); err != nil {
		return err
	}
	if !validUUIDv7(identityID) {
		return fmt.Errorf("%w: invalid SSO identity id", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "sso.unlink", "sso_identity", identityID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventSSOUnlinked, "auth.sso.unlink", actor.UserID, "", event)
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

// SSOIdentities streams the actor's linked external identities with their
// latest uses. It requires a recent interactive authentication.
func (m *Manager) SSOIdentities(ctx context.Context, actor Authentication, page PageRequest) iter.Seq2[PageEvent[SSOIdentity], error] {
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return errorSeq[PageEvent[SSOIdentity]](err)
	}
	page, err := normalizePage(page)
	if err != nil {
		return errorSeq[PageEvent[SSOIdentity]](err)
	}
	return m.store.SSOIdentities(ctx, actor.UserID, page)
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
	if (state.Operation == ssoLink || state.Operation == ssoStepUp) && state.UserID == "" {
		return ssoContinuation{}, ErrInvalidCredentials
	}
	if !m.now().Before(state.ExpiresAt) {
		return ssoContinuation{}, ErrExpired
	}
	return state, nil
}
