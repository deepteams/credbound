package credbound

import (
	"context"
	"crypto/hmac"
	"fmt"
	"iter"
	"strings"
)

const (
	passkeyRegistration   = "passkey_registration"
	passkeyAuthentication = "passkey_authentication"
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
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		UserID: actor.UserID, Operation: passkeyRegistration, Name: name,
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
	event, err := m.newAudit(ctx, actor.UserID, "passkey.create", "passkey", id, "", AuditSucceeded, "")
	if err != nil {
		return Passkey{}, err
	}
	meta, err := m.newEventMeta(EventPasskeyRegistered, "auth.passkey.registration.finish", actor.UserID, "", event)
	if err != nil {
		return Passkey{}, err
	}
	change := PasskeyRegistration{EventMeta: meta, PasskeyID: id, UserID: actor.UserID, PasskeyName: passkey.Name}
	commit := m.transactionalCommit(event, "passkey.registration", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPasskeyRegistration(ctx, tx, change)
	})
	if err := m.store.SavePasskey(ctx, passkey, commit); err != nil {
		return Passkey{}, m.mapStoreError(ctx, "auth.passkey.registration.finish", err)
	}
	passkey.CredentialJSON = nil
	registered := PasskeyRegisteredEvent{EventMeta: meta, PasskeyID: id, UserID: actor.UserID, PasskeyName: passkey.Name}
	m.events.emit(ctx, EventPasskeyRegistered, func(listener EventListener) error { return listener.OnPasskeyRegistered(ctx, registered) })
	return passkey, nil
}

// BeginPasskeyAuthentication starts a WebAuthn authentication ceremony for
// the account owning the address. No actor is required; an unknown or
// disabled account fails with the same ErrInvalidCredentials as a failed
// ceremony. Returns ErrNotSupported without Config.Passkeys.
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
	userRecord, err := m.store.UserByEmail(ctx, normalizeEmail(email))
	if err != nil || userRecord.Disabled {
		return PasskeyChallenge{}, ErrInvalidCredentials
	}
	user, err := m.passkeyUser(ctx, userRecord.ID)
	if err != nil {
		return PasskeyChallenge{}, err
	}
	options, session, err := m.passkeys.BeginAuthentication(ctx, user)
	if err != nil {
		return PasskeyChallenge{}, ErrInvalidCredentials
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		UserID: userRecord.ID, Operation: passkeyAuthentication,
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
// last-use timestamp is updated atomically with the audit event; a failed
// ceremony is audited and returns ErrInvalidCredentials.
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
	credentialID, credentialJSON, err := m.passkeys.FinishAuthentication(ctx, user, state.Session, response)
	if err != nil {
		audit, auditErr := m.recordAuthenticationAudit(ctx, state.UserID, "auth.passkey", AuditFailed, "invalid_credentials")
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.passkey.authentication.finish", audit, MethodPasskey, state.UserID, "invalid_credentials")
		return Authentication{}, ErrInvalidCredentials
	}
	event, err := m.newAudit(ctx, state.UserID, "auth.passkey", "user", state.UserID, "", AuditSucceeded, "")
	if err != nil {
		return Authentication{}, err
	}
	now := m.now()
	sealedCredential, err := m.seal(credentialJSON)
	if err != nil {
		return Authentication{}, err
	}
	passkeyID := m.passkeyIDByCredential(ctx, state.UserID, credentialID)
	if err := m.store.TouchPasskey(ctx, state.UserID, credentialID, sealedCredential, now, Commit{Audit: event}); err != nil {
		return Authentication{}, m.mapStoreError(ctx, "auth.passkey.authentication.finish", err)
	}
	authentication := Authentication{UserID: state.UserID, Method: MethodPasskey, Level: AAL2, AuthenticatedAt: now}
	if meta, metaErr := m.newEventMeta(EventPasskeyAuthenticated, "auth.passkey.authentication.finish", state.UserID, "", event); metaErr == nil {
		authenticated := PasskeyAuthenticatedEvent{EventMeta: meta, PasskeyID: passkeyID, UserID: state.UserID}
		m.events.emit(ctx, EventPasskeyAuthenticated, func(listener EventListener) error { return listener.OnPasskeyAuthenticated(ctx, authenticated) })
	}
	m.emitAuthenticationSucceeded(ctx, "auth.passkey.authentication.finish", event, authentication)
	return authentication, nil
}

// DeletePasskey removes one of the actor's passkeys, atomically with the
// audit event. It requires a fresh AAL2 step-up and works even without
// Config.Passkeys, so stale credentials remain removable.
func (m *Manager) DeletePasskey(ctx context.Context, actor Authentication, passkeyID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.delete", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.passkey.delete"); err != nil {
		return err
	}
	if passkeyID == "" {
		return fmt.Errorf("%w: passkey id is required", ErrInvalidInput)
	}
	event, err := m.newAudit(ctx, actor.UserID, "passkey.delete", "passkey", passkeyID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPasskeyDeleted, "auth.passkey.delete", actor.UserID, "", event)
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
func (m *Manager) Passkeys(ctx context.Context, actor Authentication, userID string) iter.Seq2[Passkey, error] {
	if actor.UserID == "" {
		return errorSeq[Passkey](ErrUnauthorized)
	}
	if userID == "" {
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

func (m *Manager) passkeyIDByCredential(ctx context.Context, userID string, credentialID []byte) string {
	for passkey, err := range m.store.Passkeys(ctx, userID) {
		if err != nil {
			return ""
		}
		if hmac.Equal(passkey.CredentialID, credentialID) {
			return passkey.ID
		}
	}
	return ""
}

func (m *Manager) passkeyUser(ctx context.Context, userID string) (PasskeyUser, error) {
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
