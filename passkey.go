package credbound

import (
	"context"
	"crypto/hmac"
	"fmt"
	"strings"
)

const (
	passkeyRegistration   = "passkey_registration"
	passkeyAuthentication = "passkey_authentication"
)

func (m *Manager) BeginPasskeyRegistration(ctx context.Context, actor Authentication, name string) (_ PasskeyChallenge, err error) {
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

func (m *Manager) FinishPasskeyRegistration(ctx context.Context, actor Authentication, continuation string, response []byte) (_ Passkey, err error) {
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
	event, err := m.newAudit(actor.UserID, "passkey.create", "passkey", id, "", AuditSucceeded, "")
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

func (m *Manager) BeginPasskeyAuthentication(ctx context.Context, email string) (_ PasskeyChallenge, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.authentication.begin", started, err) }()
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

func (m *Manager) FinishPasskeyAuthentication(ctx context.Context, continuation string, response []byte) (_ Authentication, err error) {
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
	event, err := m.newAudit(state.UserID, "auth.passkey", "user", state.UserID, "", AuditSucceeded, "")
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

func (m *Manager) DeletePasskey(ctx context.Context, actor Authentication, passkeyID string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.passkey.delete", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.passkey.delete"); err != nil {
		return err
	}
	if passkeyID == "" {
		return fmt.Errorf("%w: passkey id is required", ErrInvalidInput)
	}
	event, err := m.newAudit(actor.UserID, "passkey.delete", "passkey", passkeyID, "", AuditSucceeded, "")
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
