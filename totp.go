package credbound

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

const recoveryCodeCount = 10

// BeginTOTPEnrollment creates or replaces the actor's inactive TOTP factor
// and returns the otpauth URI once for the host to render; the secret is
// persisted sealed. It requires a recent interactive authentication and
// returns ErrNotSupported without Config.TOTP. The factor gates nothing
// until ConfirmTOTPEnrollment activates it.
func (m *Manager) BeginTOTPEnrollment(ctx context.Context, actor Authentication) (_ TOTPEnrollment, err error) {
	if err := m.requireTOTPProvider(); err != nil {
		return TOTPEnrollment{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.enroll.begin", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return TOTPEnrollment{}, err
	}
	user, err := m.store.UserByID(ctx, actor.UserID)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	secret, uri, err := m.totp.Generate(user.Email)
	if err != nil {
		return TOTPEnrollment{}, fmt.Errorf("generate totp secret: %w", err)
	}
	encrypted, err := m.seal([]byte(secret))
	if err != nil {
		return TOTPEnrollment{}, err
	}
	now := m.now()
	factor := TOTPFactor{UserID: actor.UserID, EncryptedSecret: encrypted, CreatedAt: now, UpdatedAt: now}
	event, err := m.newAudit(ctx, actor.UserID, "totp.enrollment.begin", "user", actor.UserID, "", AuditSucceeded, "")
	if err != nil {
		return TOTPEnrollment{}, err
	}
	meta, err := m.newEventMeta(EventTOTPEnrollmentStarted, "auth.totp.enroll.begin", actor.UserID, "", event)
	if err != nil {
		return TOTPEnrollment{}, err
	}
	change := TOTPEnrollmentChange{EventMeta: meta, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "totp.enrollment", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyTOTPEnrollment(ctx, tx, change)
	})
	if err := m.store.SaveTOTPEnrollment(ctx, factor, commit); err != nil {
		return TOTPEnrollment{}, m.mapStoreError(ctx, "auth.totp.enroll.begin", err)
	}
	startedEvent := TOTPEnrollmentStartedEvent{EventMeta: meta, UserID: actor.UserID}
	m.events.emit(ctx, EventTOTPEnrollmentStarted, func(listener EventListener) error { return listener.OnTOTPEnrollmentStarted(ctx, startedEvent) })
	return TOTPEnrollment{URI: uri}, nil
}

// ConfirmTOTPEnrollment activates the pending factor after proving a valid
// code and returns the single-use recovery codes exactly once; only their
// peppered digests are persisted. It requires a recent interactive
// authentication and returns ErrNotSupported without Config.TOTP, ErrNotFound
// without a pending enrollment, and ErrInvalidCredentials for a wrong code.
func (m *Manager) ConfirmTOTPEnrollment(ctx context.Context, actor Authentication, code string) (_ []string, err error) {
	if err := m.requireTOTPProvider(); err != nil {
		return nil, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.enroll.confirm", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return nil, err
	}
	factor, err := m.store.TOTPByUserID(ctx, actor.UserID)
	if err != nil || factor.Active {
		return nil, ErrNotFound
	}
	secret, err := m.decryptTOTPSecret(factor)
	if err != nil {
		return nil, err
	}
	step, valid := m.totp.Validate(strings.TrimSpace(code), secret, m.now())
	if !valid {
		if auditErr := m.appendAuthenticationAudit(ctx, actor.UserID, "totp.enrollment.confirm", AuditFailed, "invalid_credentials"); auditErr != nil {
			return nil, auditErr
		}
		return nil, ErrInvalidCredentials
	}
	codes, records, err := m.generateRecoveryCodes(actor.UserID)
	if err != nil {
		return nil, err
	}
	factor.Active = true
	// Record the enrollment code's step as consumed so it cannot be replayed as
	// a full second factor through VerifyTOTP within its remaining window.
	factor.LastUsedStep = step
	factor.UpdatedAt = m.now()
	event, err := m.newAudit(ctx, actor.UserID, "totp.enrollment.confirm", "user", actor.UserID, "", AuditSucceeded, "")
	if err != nil {
		return nil, err
	}
	meta, err := m.newEventMeta(EventTOTPActivated, "auth.totp.enroll.confirm", actor.UserID, "", event)
	if err != nil {
		return nil, err
	}
	change := TOTPActivation{EventMeta: meta, UserID: actor.UserID, RecoveryCodeCount: len(records)}
	commit := m.transactionalCommit(event, "totp.activation", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyTOTPActivation(ctx, tx, change)
	})
	if err := m.store.ActivateTOTP(ctx, factor, records, commit); err != nil {
		return nil, m.mapStoreError(ctx, "auth.totp.enroll.confirm", err)
	}
	activated := TOTPActivatedEvent{EventMeta: meta, UserID: actor.UserID, RecoveryCodeCount: len(records)}
	m.events.emit(ctx, EventTOTPActivated, func(listener EventListener) error { return listener.OnTOTPActivated(ctx, activated) })
	return codes, nil
}

// VerifyTOTP validates a TOTP or single-use recovery code for an
// interactive actor and returns a fresh AAL2 authentication — the second
// step of the password-then-TOTP flow the host stores in place of the AAL1
// context. Replays of an already accepted time step and wrong codes fail
// with ErrInvalidCredentials; wrong codes count toward the account lockout
// (ErrLocked while it lasts). Returns ErrNotSupported without Config.TOTP.
func (m *Manager) VerifyTOTP(ctx context.Context, actor Authentication, code string) (_ Authentication, err error) {
	if err := m.requireTOTPProvider(); err != nil {
		return Authentication{}, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.verify", started, err) }()
	if actor.UserID == "" || !actor.Interactive() {
		return Authentication{}, ErrUnauthorized
	}
	if err := m.requireUnlocked(ctx, actor.UserID, "auth.totp"); err != nil {
		return Authentication{}, err
	}
	// Refuse to promote a disabled account to AAL2, even though the actor
	// proved a first factor before it was disabled.
	if err := m.requireActiveUser(ctx, actor.UserID); err != nil {
		return Authentication{}, err
	}
	factor, err := m.store.TOTPByUserID(ctx, actor.UserID)
	if err != nil || !factor.Active {
		return Authentication{}, ErrInvalidCredentials
	}
	secret, err := m.decryptTOTPSecret(factor)
	if err != nil {
		return Authentication{}, err
	}
	normalized := strings.TrimSpace(code)
	step, valid := m.totp.Validate(normalized, secret, m.now())
	if valid {
		event, eventErr := m.newAudit(ctx, actor.UserID, "auth.totp", "user", actor.UserID, "", AuditSucceeded, "")
		if eventErr != nil {
			return Authentication{}, eventErr
		}
		used, useErr := m.store.UseTOTP(ctx, actor.UserID, step, Commit{Audit: event})
		if useErr != nil {
			return Authentication{}, m.mapStoreError(ctx, "auth.totp.verify", useErr)
		}
		if !used {
			failedAudit, auditErr := m.recordAuthenticationAudit(ctx, actor.UserID, "auth.totp", AuditFailed, "invalid_credentials")
			if auditErr != nil {
				return Authentication{}, auditErr
			}
			meta, metaErr := m.newEventMeta(EventTOTPReplayRejected, "auth.totp.verify", actor.UserID, "", failedAudit)
			if metaErr == nil {
				rejected := TOTPReplayRejectedEvent{EventMeta: meta, UserID: actor.UserID}
				m.events.emit(ctx, EventTOTPReplayRejected, func(listener EventListener) error { return listener.OnTOTPReplayRejected(ctx, rejected) })
			}
			m.emitAuthenticationFailed(ctx, "auth.totp.verify", failedAudit, MethodTOTP, actor.UserID, "invalid_credentials")
			return Authentication{}, ErrInvalidCredentials
		}
		promoted := m.promoteTOTP(actor)
		meta, metaErr := m.newEventMeta(EventTOTPVerified, "auth.totp.verify", actor.UserID, "", event)
		if metaErr == nil {
			verified := TOTPVerifiedEvent{EventMeta: meta, UserID: actor.UserID}
			m.events.emit(ctx, EventTOTPVerified, func(listener EventListener) error { return listener.OnTOTPVerified(ctx, verified) })
		}
		m.emitAuthenticationSucceeded(ctx, "auth.totp.verify", event, promoted)
		return promoted, nil
	}

	event, eventErr := m.newAudit(ctx, actor.UserID, "auth.recovery_code", "user", actor.UserID, "", AuditSucceeded, "")
	if eventErr != nil {
		return Authentication{}, eventErr
	}
	// The pepper ring (active first, then retired) keeps recovery codes
	// issued before a rotation consumable; a miss never writes the audit,
	// so at most one attempt commits.
	used := false
	for _, pepper := range m.readRecoveryPeppers {
		recoveryDigest := digest(pepper, normalizeRecoveryCode(normalized))
		var consumeErr error
		used, consumeErr = m.store.ConsumeRecoveryCode(ctx, actor.UserID, recoveryDigest, m.now(), Commit{Audit: event})
		if consumeErr != nil {
			return Authentication{}, m.mapStoreError(ctx, "auth.totp.verify", consumeErr)
		}
		if used {
			break
		}
	}
	if used {
		promoted := m.promoteTOTP(actor)
		meta, metaErr := m.newEventMeta(EventRecoveryCodeConsumed, "auth.totp.verify", actor.UserID, "", event)
		if metaErr == nil {
			consumed := RecoveryCodeConsumedEvent{EventMeta: meta, UserID: actor.UserID}
			m.events.emit(ctx, EventRecoveryCodeConsumed, func(listener EventListener) error { return listener.OnRecoveryCodeConsumed(ctx, consumed) })
		}
		m.emitAuthenticationSucceeded(ctx, "auth.totp.verify", event, promoted)
		return promoted, nil
	}
	failedAudit, auditErr := m.recordAuthenticationFailure(ctx, actor.UserID, "auth.totp", true)
	if auditErr != nil {
		return Authentication{}, auditErr
	}
	m.emitAuthenticationFailed(ctx, "auth.totp.verify", failedAudit, MethodTOTP, actor.UserID, "invalid_credentials")
	return Authentication{}, ErrInvalidCredentials
}

// DisableTOTP removes the actor's active TOTP factor and its recovery codes
// after re-proving possession of a valid code, atomically with the audit
// event. The verification itself yields the fresh AAL2 step-up the removal
// requires. Returns ErrNotSupported without Config.TOTP.
func (m *Manager) DisableTOTP(ctx context.Context, actor Authentication, code string) (err error) {
	if err := m.requireTOTPProvider(); err != nil {
		return err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.disable", started, err) }()
	promoted, err := m.VerifyTOTP(ctx, actor, code)
	if err != nil {
		return err
	}
	if err := m.requireStepUp(ctx, promoted, "auth.totp.disable"); err != nil {
		return err
	}
	event, err := m.newAudit(ctx, actor.UserID, "totp.disable", "user", actor.UserID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventTOTPDisabled, "auth.totp.disable", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := TOTPDisable{EventMeta: meta, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "totp.disable", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyTOTPDisable(ctx, tx, change)
	})
	if err := m.store.DisableTOTP(ctx, actor.UserID, commit); err != nil {
		return m.mapStoreError(ctx, "auth.totp.disable", err)
	}
	disabled := TOTPDisabledEvent{EventMeta: meta, UserID: actor.UserID}
	m.events.emit(ctx, EventTOTPDisabled, func(listener EventListener) error { return listener.OnTOTPDisabled(ctx, disabled) })
	return nil
}

// RegenerateRecoveryCodes replaces the actor's recovery codes with a fresh
// set returned exactly once; the previous codes stop working in the same
// transaction, so a user who suspects their codes leaked — or has consumed
// most of them — rotates the set without re-enrolling TOTP. It requires an
// active TOTP factor and a fresh interactive AAL2 authentication. Returns
// ErrNotSupported without Config.TOTP and ErrNotFound without an active
// factor.
func (m *Manager) RegenerateRecoveryCodes(ctx context.Context, actor Authentication) (_ []string, err error) {
	if err := m.requireTOTPProvider(); err != nil {
		return nil, err
	}
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.recovery.regenerate", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.totp.recovery.regenerate"); err != nil {
		return nil, err
	}
	factor, err := m.store.TOTPByUserID(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	if !factor.Active {
		return nil, ErrNotFound
	}
	codes, records, err := m.generateRecoveryCodes(actor.UserID)
	if err != nil {
		return nil, err
	}
	event, err := m.newAudit(ctx, actor.UserID, "totp.recovery.regenerate", "user", actor.UserID, "", AuditSucceeded, "")
	if err != nil {
		return nil, err
	}
	meta, err := m.newEventMeta(EventRecoveryCodesRegenerated, "auth.totp.recovery.regenerate", actor.UserID, "", event)
	if err != nil {
		return nil, err
	}
	change := RecoveryCodeRegeneration{EventMeta: meta, UserID: actor.UserID, RecoveryCodeCount: len(records)}
	commit := m.transactionalCommit(event, "totp.recovery.regeneration", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyRecoveryCodeRegeneration(ctx, tx, change)
	})
	if err := m.store.ReplaceRecoveryCodes(ctx, actor.UserID, records, commit); err != nil {
		return nil, m.mapStoreError(ctx, "auth.totp.recovery.regenerate", err)
	}
	regenerated := RecoveryCodesRegeneratedEvent{EventMeta: meta, UserID: actor.UserID, RecoveryCodeCount: len(records)}
	m.events.emit(ctx, EventRecoveryCodesRegenerated, func(listener EventListener) error { return listener.OnRecoveryCodesRegenerated(ctx, regenerated) })
	return codes, nil
}

// TOTPStatus reports whether a user has a TOTP factor, whether it is active,
// and how many recovery codes remain unused. It never exposes the secret.
// Reading another user requires admin users read permission.
func (m *Manager) TOTPStatus(ctx context.Context, actor Authentication, userID string) (_ TOTPStatus, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.totp.status", started, err) }()
	if actor.UserID == "" {
		return TOTPStatus{}, ErrUnauthorized
	}
	if userID == "" {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return TOTPStatus{}, err
		}
	} else if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
		return TOTPStatus{}, err
	}
	factor, err := m.store.TOTPByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return TOTPStatus{}, nil
		}
		return TOTPStatus{}, err
	}
	status := TOTPStatus{Enrolled: true, Active: factor.Active, CreatedAt: factor.CreatedAt, UpdatedAt: factor.UpdatedAt}
	if factor.Active {
		remaining, err := m.store.CountUnusedRecoveryCodes(ctx, userID)
		if err != nil {
			return TOTPStatus{}, err
		}
		status.UnusedRecoveryCodes = int(remaining)
	}
	return status, nil
}

func (m *Manager) decryptTOTPSecret(factor TOTPFactor) (string, error) {
	plaintext, err := m.open(factor.EncryptedSecret)
	if err != nil {
		return "", fmt.Errorf("decrypt totp secret: %w", err)
	}
	return string(plaintext), nil
}

func (m *Manager) generateRecoveryCodes(userID string) ([]string, []RecoveryCode, error) {
	codes := make([]string, 0, recoveryCodeCount)
	records := make([]RecoveryCode, 0, recoveryCodeCount)
	for range recoveryCodeCount {
		raw, err := randomBytes(m.random, 10)
		if err != nil {
			return nil, nil, err
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
		code := encoded[:4] + "-" + encoded[4:8] + "-" + encoded[8:12] + "-" + encoded[12:]
		codes = append(codes, code)
		records = append(records, RecoveryCode{UserID: userID, Digest: digest(m.recoveryPepper, normalizeRecoveryCode(code))})
	}
	return codes, records, nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
}

func (m *Manager) promoteTOTP(actor Authentication) Authentication {
	return Authentication{UserID: actor.UserID, Method: MethodTOTP, Level: AAL2, AuthenticatedAt: m.now()}
}

// requireTOTPProvider gates the flows that need Config.TOTP; a manager built
// without one supports every other capability and reports ErrNotSupported
// here, mirroring the optional SCIM and OAuth stores.
func (m *Manager) requireTOTPProvider() error {
	if m.totp == nil {
		return fmt.Errorf("%w: no TOTP provider configured", ErrNotSupported)
	}
	return nil
}
