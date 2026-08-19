package credbound

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"iter"
	"strings"
)

const (
	passkeyRegistration   = "passkey_registration"
	passkeyAuthentication = "passkey_authentication"
	passkeyDiscoverable   = "passkey_discoverable"
)

// BeginPasskeyRegistration starts a WebAuthn registration ceremony for the
// actor and returns the browser options with a sealed continuation bound to
// the user, operation and expiry. It requires a recent interactive
// authentication and returns ErrNotSupported without Config.Passkeys.
func (m *Manager) BeginPasskeyRegistration(ctx context.Context, actor Authentication, name string) (_ PasskeyChallenge, err error) {
	if err := m.requirePasskeyProvider(); err != nil {
		return PasskeyChallenge{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.registration.begin", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return PasskeyChallenge{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return PasskeyChallenge{}, fmt.Errorf("%w: passkey name is required and limited to 100 characters", ErrInvalidInput)
	}
	user, err := m.passkeyUser(ctx, actor.UserID)
	if err != nil {
		return PasskeyChallenge{}, err
	}
	options, session, err := m.passkeys.BeginRegistration(ctx, user)
	if err != nil {
		return PasskeyChallenge{}, fmt.Errorf("begin passkey registration: %w", err)
	}
	ceremonyID, err := m.newID()
	if err != nil {
		return PasskeyChallenge{}, err
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		ID: ceremonyID, UserID: actor.UserID, Operation: passkeyRegistration, Name: name,
		ExpiresAt: m.now().Add(m.ceremonyTTL), Session: session,
	})
	if err != nil {
		return PasskeyChallenge{}, err
	}
	return PasskeyChallenge{Options: options, Continuation: continuation}, nil
}

// FinishPasskeyRegistration validates the browser response against the
// sealed continuation and persists the new passkey, atomically with the
// audit event. The continuation must belong to the same actor, who still
// needs a recent interactive authentication; a failed ceremony is audited
// and returns ErrInvalidCredentials. The returned Passkey carries no
// credential material.
func (m *Manager) FinishPasskeyRegistration(ctx context.Context, actor Authentication, continuation string, response []byte) (_ Passkey, err error) {
	if err := m.requirePasskeyProvider(); err != nil {
		return Passkey{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.registration.finish", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return Passkey{}, err
	}
	state, err := m.decodeContinuation(continuation, passkeyRegistration)
	if err != nil {
		return Passkey{}, err
	}
	if state.UserID != actor.UserID {
		return Passkey{}, ErrInvalidCredentials
	}
	user, err := m.passkeyUser(ctx, actor.UserID)
	if err != nil {
		return Passkey{}, err
	}
	credentialID, credentialJSON, err := m.passkeys.FinishRegistration(ctx, user, state.Session, response)
	if err != nil {
		if auditErr := m.appendAuthenticationAudit(ctx, actor.UserID, "passkey.registration", AuditFailed, "invalid_credentials"); auditErr != nil {
			return Passkey{}, auditErr
		}
		return Passkey{}, ErrInvalidCredentials
	}
	if len(credentialID) == 0 || len(credentialJSON) == 0 {
		return Passkey{}, fmt.Errorf("%w: passkey provider returned an empty credential", ErrInvalidInput)
	}
	sealedCredential, err := m.seal(credentialJSON)
	if err != nil {
		return Passkey{}, err
	}
	id, err := m.newID()
	if err != nil {
		return Passkey{}, err
	}
	passkey := Passkey{
		ID: id, UserID: actor.UserID, Name: state.Name,
		CredentialID:   append([]byte(nil), credentialID...),
		CredentialJSON: sealedCredential, CreatedAt: m.now(),
	}
	event, err := m.newAudit(ctx, actor.UserID, "passkey.create", "passkey", id.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return Passkey{}, err
	}
	meta, err := m.newEventMeta(EventPasskeyRegistered, "auth.passkey.registration.finish", actor.UserID, UUID{}, event)
	if err != nil {
		return Passkey{}, err
	}
	change := PasskeyRegistration{EventMeta: meta, PasskeyID: id, UserID: actor.UserID, PasskeyName: passkey.Name}
	commit := m.transactionalCommit(event, "passkey.registration", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPasskeyRegistration(ctx, tx, change)
	})
	// The ceremony is single use: the success commit consumes its id, so a
	// replayed continuation can never register a second credential.
	commit.Ceremony = state.consumption()
	if err := m.store.SavePasskey(ctx, passkey, commit); err != nil {
		return Passkey{}, m.mapStoreError(ctx, "auth.passkey.registration.finish", err)
	}
	passkey.CredentialJSON = nil
	registered := PasskeyRegisteredEvent{EventMeta: meta, PasskeyID: id, UserID: actor.UserID, PasskeyName: passkey.Name}
	m.events.emit(ctx, EventPasskeyRegistered, func(listener EventListener) error { return listener.OnPasskeyRegistered(ctx, registered) })
	return passkey, nil
}

// BeginPasskeyAuthentication starts a WebAuthn authentication ceremony for
// the account owning the address. No actor is required. An address that
// cannot authenticate — unknown, disabled, or with no passkey — is answered
// with a decoy challenge indistinguishable from a real one, so the response
// never reveals whether the account exists or holds a passkey; the decoy
// fails at FinishPasskeyAuthentication like any wrong credential. Returns
// ErrNotSupported without Config.Passkeys.
func (m *Manager) BeginPasskeyAuthentication(ctx context.Context, email string) (_ PasskeyChallenge, err error) {
	if err := m.requirePasskeyProvider(); err != nil {
		return PasskeyChallenge{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.authentication.begin", started, err) }()
	// SSO-006: a confirmed EnforceSSO domain rejects every interactive
	// non-SSO flow, including passkeys registered before the policy was
	// enabled. Checked before any lookup so the answer depends only on the
	// domain. Non-interactive PATs are deliberately exempt, like the
	// workspace MFA policy.
	if err := m.domainRequiresSSO(ctx, normalizeEmail(email), "passkey.authentication.begin"); err != nil {
		return PasskeyChallenge{}, err
	}
	normalized := normalizeEmail(email)
	userRecord, err := m.store.UserByEmail(ctx, normalized)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// An unknown address is answered with a decoy challenge, not an
			// error: the response never reveals whether the account exists.
			return m.decoyPasskeyChallenge(ctx, normalized)
		}
		return PasskeyChallenge{}, err
	}
	if userRecord.Disabled {
		return m.decoyPasskeyChallenge(ctx, normalized)
	}
	user, err := m.passkeyUser(ctx, userRecord.ID)
	if err != nil {
		return PasskeyChallenge{}, err
	}
	options, session, err := m.passkeys.BeginAuthentication(ctx, user)
	if err != nil {
		// A user with no passkey is answered with a decoy so passkey presence
		// stays hidden; any other ceremony error (a corrupt stored credential,
		// an offline provider) still fails closed.
		if errors.Is(err, ErrNoPasskey) {
			return m.decoyPasskeyChallenge(ctx, normalized)
		}
		return PasskeyChallenge{}, ErrInvalidCredentials
	}
	ceremonyID, err := m.newID()
	if err != nil {
		return PasskeyChallenge{}, err
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		ID: ceremonyID, UserID: userRecord.ID, Operation: passkeyAuthentication,
		ExpiresAt: m.now().Add(m.ceremonyTTL), Session: session,
	})
	if err != nil {
		return PasskeyChallenge{}, err
	}
	return PasskeyChallenge{Options: options, Continuation: continuation}, nil
}

// decoyPasskeyChallenge answers an address that cannot authenticate with a
// passkey — unknown, disabled, or without one — with a challenge structurally
// indistinguishable from a real one, closing the passkey-presence and
// account-existence enumeration oracle. The seed is stable per address so
// repeated probes see the same fabricated credentials. Its continuation carries
// no user id, so FinishPasskeyAuthentication fails it as invalid credentials.
// A residual signal remains — the fabricated allowCredentials list holds one
// entry, so an account with several passkeys is still distinguishable by
// count; BeginDiscoverablePasskeyAuthentication closes that fully by asking
// for no address at all.
func (m *Manager) decoyPasskeyChallenge(ctx context.Context, normalizedEmail string) (PasskeyChallenge, error) {
	seed := digest(m.digestKey, "passkey-decoy:"+normalizedEmail)
	options, session, err := m.passkeys.BeginDecoyAuthentication(ctx, seed)
	if err != nil {
		return PasskeyChallenge{}, ErrInvalidCredentials
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		Operation: passkeyAuthentication,
		ExpiresAt: m.now().Add(m.ceremonyTTL), Session: session,
	})
	if err != nil {
		return PasskeyChallenge{}, err
	}
	return PasskeyChallenge{Options: options, Continuation: continuation}, nil
}

// FinishPasskeyAuthentication validates the browser response against the
// sealed continuation and returns an AAL2 interactive authentication — a
// user-verified passkey ceremony needs no second factor. The passkey's
// last-use timestamp is updated atomically with the audit event, and the
// same commit consumes the single-use ceremony, so a captured response can
// never be replayed — WebAuthn signature counters alone cannot guarantee
// that, since many authenticators legitimately report a constant zero. A
// failed or replayed ceremony is audited and returns ErrInvalidCredentials.
func (m *Manager) FinishPasskeyAuthentication(ctx context.Context, continuation string, response []byte) (_ Authentication, err error) {
	if err := m.requirePasskeyProvider(); err != nil {
		return Authentication{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.authentication.finish", started, err) }()
	state, err := m.decodeContinuation(continuation, passkeyAuthentication)
	if err != nil {
		return Authentication{}, err
	}
	user, err := m.passkeyUser(ctx, state.UserID)
	if err != nil {
		return Authentication{}, ErrInvalidCredentials
	}
	// The account can be disabled between Begin (which serves a decoy for a
	// disabled user) and Finish. Re-check here so the ceremony cannot mint an
	// AAL2 authentication for a disabled account, mirroring AuthenticatePassword
	// and FinishSSO.
	record, lookupErr := m.store.UserByID(ctx, state.UserID)
	if lookupErr != nil || record.Disabled {
		return Authentication{}, ErrInvalidCredentials
	}
	// SSO-006: the policy can also be confirmed between Begin and Finish, so
	// the resolved account's primary address is re-checked exactly like the
	// discoverable flow — an in-flight ceremony must not outlive an
	// EnforceSSO confirmation.
	if ssoErr := m.domainRequiresSSO(ctx, normalizeEmail(record.Email), "passkey.authentication.finish"); ssoErr != nil {
		return Authentication{}, ssoErr
	}
	credentialID, credentialJSON, err := m.passkeys.FinishAuthentication(ctx, user, state.Session, response)
	if err != nil {
		reason := "invalid_credentials"
		if errors.Is(err, ErrPasskeyCloneDetected) {
			// A regressed signature counter means the authenticator may be
			// cloned; surface it distinctly so a host can alert and revoke.
			reason = "cloned_authenticator"
		}
		audit, auditErr := m.recordAuthenticationAudit(ctx, state.UserID, "auth.passkey", AuditFailed, reason)
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.passkey.authentication.finish", audit, MethodPasskey, state.UserID, reason)
		return Authentication{}, ErrInvalidCredentials
	}
	return m.commitPasskeyAuthentication(ctx, "auth.passkey.authentication.finish", state, state.UserID, credentialID, credentialJSON)
}

// commitPasskeyAuthentication is the shared success tail of the two passkey
// sign-in flows: it touches the credential, consumes the single-use ceremony
// in the same commit, and mints the AAL2 authentication.
func (m *Manager) commitPasskeyAuthentication(ctx context.Context, operation string, state ceremonyContinuation, userID UUID, credentialID, credentialJSON []byte) (Authentication, error) {
	event, err := m.newAudit(ctx, userID, "auth.passkey", "user", userID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	now := m.now()
	sealedCredential, err := m.seal(credentialJSON)
	if err != nil {
		return Authentication{}, err
	}
	passkeyID := m.passkeyIDByCredential(ctx, userID, credentialID)
	if err := m.store.TouchPasskey(ctx, userID, credentialID, sealedCredential, now, Commit{Audit: event, Ceremony: state.consumption()}); err != nil {
		if errors.Is(err, ErrConflict) {
			// The ceremony was already consumed: a replayed response can
			// never mint a second authentication — even for authenticators
			// whose signature counter stays at zero — and answers like any
			// invalid credential.
			return Authentication{}, ErrInvalidCredentials
		}
		return Authentication{}, m.mapStoreError(ctx, operation, err)
	}
	authentication := Authentication{UserID: userID, Method: MethodPasskey, Level: AAL2, AuthenticatedAt: now}
	if meta, metaErr := m.newEventMeta(EventPasskeyAuthenticated, operation, userID, UUID{}, event); metaErr == nil {
		authenticated := PasskeyAuthenticatedEvent{EventMeta: meta, PasskeyID: passkeyID, UserID: userID}
		m.events.emit(ctx, EventPasskeyAuthenticated, func(listener EventListener) error { return listener.OnPasskeyAuthenticated(ctx, authenticated) })
	}
	m.emitAuthenticationSucceeded(ctx, operation, event, authentication)
	return authentication, nil
}

// BeginDiscoverablePasskeyAuthentication starts a usernameless WebAuthn
// ceremony: no address is asked and the challenge carries an empty
// allowCredentials list, so the authenticator offers its discoverable
// credentials. Because the challenge is bound to no account, there is no
// per-address answer left to probe — this closes the residual enumeration
// signal of the per-address decoy, whose fabricated allowCredentials list
// holds one entry while a real account may show several. It requires a
// provider implementing DiscoverablePasskeyProvider and a
// PasskeyCredentialStore-capable store; otherwise it returns
// ErrNotSupported.
func (m *Manager) BeginDiscoverablePasskeyAuthentication(ctx context.Context) (_ PasskeyChallenge, err error) {
	provider, _, err := m.discoverablePasskeys()
	if err != nil {
		return PasskeyChallenge{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.discoverable.begin", started, err) }()
	options, session, err := provider.BeginDiscoverableAuthentication(ctx)
	if err != nil {
		return PasskeyChallenge{}, ErrInvalidCredentials
	}
	ceremonyID, err := m.newID()
	if err != nil {
		return PasskeyChallenge{}, err
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		ID: ceremonyID, Operation: passkeyDiscoverable,
		ExpiresAt: m.now().Add(m.ceremonyTTL), Session: session,
	})
	if err != nil {
		return PasskeyChallenge{}, err
	}
	return PasskeyChallenge{Options: options, Continuation: continuation}, nil
}

// FinishDiscoverablePasskeyAuthentication validates the browser response of
// a discoverable ceremony, resolves the account from the asserted credential,
// and returns an AAL2 interactive authentication with the same single-use
// ceremony consumption as FinishPasskeyAuthentication. A disabled account
// and a confirmed EnforceSSO domain are refused — the domain policy, checked
// by address at Begin in the email-first flow, is enforced here against the
// resolved account's primary address.
func (m *Manager) FinishDiscoverablePasskeyAuthentication(ctx context.Context, continuation string, response []byte) (_ Authentication, err error) {
	provider, credentialStore, err := m.discoverablePasskeys()
	if err != nil {
		return Authentication{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.discoverable.finish", started, err) }()
	state, err := m.decodeContinuation(continuation, passkeyDiscoverable)
	if err != nil {
		return Authentication{}, err
	}
	resolvedUserID := UUID{}
	lookup := func(ctx context.Context, credentialID []byte) (PasskeyUser, error) {
		passkey, lookupErr := credentialStore.PasskeyByCredentialID(ctx, credentialID)
		if lookupErr != nil {
			return PasskeyUser{}, lookupErr
		}
		user, lookupErr := m.passkeyUser(ctx, passkey.UserID)
		if lookupErr != nil {
			return PasskeyUser{}, lookupErr
		}
		resolvedUserID = passkey.UserID
		return user, nil
	}
	credentialID, credentialJSON, err := provider.FinishDiscoverableAuthentication(ctx, state.Session, response, lookup)
	if err != nil {
		if resolvedUserID == (UUID{}) {
			// The assertion never resolved to an account, so there is no
			// actor to audit; the caller learns nothing but failure.
			return Authentication{}, ErrInvalidCredentials
		}
		reason := "invalid_credentials"
		if errors.Is(err, ErrPasskeyCloneDetected) {
			reason = "cloned_authenticator"
		}
		audit, auditErr := m.recordAuthenticationAudit(ctx, resolvedUserID, "auth.passkey", AuditFailed, reason)
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.passkey.discoverable.finish", audit, MethodPasskey, resolvedUserID, reason)
		return Authentication{}, ErrInvalidCredentials
	}
	if resolvedUserID == (UUID{}) {
		return Authentication{}, ErrInvalidCredentials
	}
	record, lookupErr := m.store.UserByID(ctx, resolvedUserID)
	if lookupErr != nil || record.Disabled {
		return Authentication{}, ErrInvalidCredentials
	}
	// SSO-006: the resolved account's primary address decides the policy, so
	// a passkey registered before EnforceSSO was confirmed cannot bypass it
	// through the usernameless flow.
	if ssoErr := m.domainRequiresSSO(ctx, normalizeEmail(record.Email), "passkey.discoverable.finish"); ssoErr != nil {
		return Authentication{}, ssoErr
	}
	return m.commitPasskeyAuthentication(ctx, "auth.passkey.discoverable.finish", state, resolvedUserID, credentialID, credentialJSON)
}

// discoverablePasskeys resolves the optional capabilities the usernameless
// flow needs, failing with ErrNotSupported when either side lacks them.
func (m *Manager) discoverablePasskeys() (DiscoverablePasskeyProvider, PasskeyCredentialStore, error) {
	if err := m.requirePasskeyProvider(); err != nil {
		return nil, nil, err
	}
	provider, ok := m.passkeys.(DiscoverablePasskeyProvider)
	if !ok {
		return nil, nil, fmt.Errorf("%w: passkey provider does not support discoverable authentication", ErrNotSupported)
	}
	credentialStore, ok := m.store.(PasskeyCredentialStore)
	if !ok {
		return nil, nil, fmt.Errorf("%w: store does not implement PasskeyCredentialStore", ErrNotSupported)
	}
	return provider, credentialStore, nil
}

// DeletePasskey removes one of the actor's passkeys, atomically with the
// audit event. It requires a fresh AAL2 step-up and works even without
// Config.Passkeys, so stale credentials remain removable.
func (m *Manager) DeletePasskey(ctx context.Context, actor Authentication, passkeyID UUID) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.delete", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.passkey.delete"); err != nil {
		return err
	}
	if passkeyID == (UUID{}) {
		return fmt.Errorf("%w: passkey id is required", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "passkey.delete", "passkey", passkeyID.String(), UUID{}, AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPasskeyDeleted, "auth.passkey.delete", actor.UserID, UUID{}, event)
	if err != nil {
		return err
	}
	change := PasskeyDeletion{EventMeta: meta, PasskeyID: passkeyID, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "passkey.deletion", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPasskeyDeletion(ctx, tx, change)
	})
	if err := m.store.DeletePasskey(ctx, actor.UserID, passkeyID, commit); err != nil {
		return m.mapStoreError(ctx, "auth.passkey.delete", err)
	}
	deleted := PasskeyDeletedEvent{EventMeta: meta, PasskeyID: passkeyID, UserID: actor.UserID}
	m.events.emit(ctx, EventPasskeyDeleted, func(listener EventListener) error { return listener.OnPasskeyDeleted(ctx, deleted) })
	return nil
}

// Passkeys streams the metadata of a user's registered passkeys so the host
// can render a credential-management page. The sealed credential material is
// never exposed. Reading another user requires admin users read permission.
func (m *Manager) Passkeys(ctx context.Context, actor Authentication, userID UUID) iter.Seq2[Passkey, error] {
	if actor.UserID == (UUID{}) {
		return errorSeq[Passkey](ErrUnauthorized)
	}
	if userID == (UUID{}) {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return errorSeq[Passkey](err)
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return errorSeq[Passkey](err)
	}
	return func(yield func(Passkey, error) bool) {
		for passkey, err := range m.store.Passkeys(ctx, userID) {
			if err != nil {
				yield(Passkey{}, err)
				return
			}
			passkey.CredentialJSON = nil
			if !yield(passkey, nil) {
				return
			}
		}
	}
}

func (m *Manager) passkeyIDByCredential(ctx context.Context, userID UUID, credentialID []byte) UUID {
	for passkey, err := range m.store.Passkeys(ctx, userID) {
		if err != nil {
			return UUID{}
		}
		if hmac.Equal(passkey.CredentialID, credentialID) {
			return passkey.ID
		}
	}
	return UUID{}
}

func (m *Manager) passkeyUser(ctx context.Context, userID UUID) (PasskeyUser, error) {
	user, err := m.store.UserByID(ctx, userID)
	if err != nil {
		return PasskeyUser{}, err
	}
	credentials := func(yield func(Passkey, error) bool) {
		for passkey, err := range m.store.Passkeys(ctx, userID) {
			if err != nil {
				yield(Passkey{}, err)
				return
			}
			plaintext, err := m.open(passkey.CredentialJSON)
			if err != nil {
				yield(Passkey{}, fmt.Errorf("decrypt passkey credential: %w", err))
				return
			}
			passkey.CredentialJSON = plaintext
			if !yield(passkey, nil) {
				return
			}
		}
	}
	return PasskeyUser{User: user, Credentials: credentials}, nil
}

// requirePasskeyProvider gates the WebAuthn ceremonies that need
// Config.Passkeys; a manager built without one supports every other
// capability and reports ErrNotSupported here.
func (m *Manager) requirePasskeyProvider() error {
	if m.passkeys == nil {
		return fmt.Errorf("%w: no passkey provider configured", ErrNotSupported)
	}
	return nil
}
