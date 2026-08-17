package credbound

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

func (m *Manager) Bootstrap(ctx context.Context, input BootstrapInput) (_ Authentication, _ Workspace, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.bootstrap", started, err) }()

	email, err := validEmail(input.Email)
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	if strings.TrimSpace(input.DisplayName) == "" || strings.TrimSpace(input.WorkspaceName) == "" {
		return Authentication{}, Workspace{}, fmt.Errorf("%w: display name and workspace name are required", ErrInvalidInput)
	}
	if err := m.validatePassword(input.Password); err != nil {
		return Authentication{}, Workspace{}, err
	}
	hash, err := m.passwords.Hash(input.Password)
	if err != nil {
		return Authentication{}, Workspace{}, fmt.Errorf("hash password: %w", err)
	}
	userID, err := m.newID()
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	workspaceID, err := m.newID()
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	now := m.now()
	user := User{ID: userID, Email: email, DisplayName: strings.TrimSpace(input.DisplayName), LastSeenAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	primaryEmail := EmailAddress{ID: emailID, UserID: userID, Address: email, Primary: true, VerifiedAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	workspace := Workspace{ID: workspaceID, Name: strings.TrimSpace(input.WorkspaceName), CreatedAt: now, UpdatedAt: now}
	membership := Membership{WorkspaceID: workspace.ID, UserID: user.ID, Role: RoleAdmin, Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now}
	instanceAdmin := InstanceAdministrator{UserID: user.ID, Role: InstanceRoleRoot, CreatedAt: now, UpdatedAt: now}
	event, err := m.newAudit(ctx, user.ID, "instance.bootstrap", "workspace", workspace.ID, workspace.ID, AuditSucceeded, "")
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	userMeta, err := m.newEventMeta(EventUserCreated, "auth.bootstrap", user.ID, workspace.ID, event)
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	workspaceMeta, err := m.newEventMeta(EventWorkspaceCreated, "auth.bootstrap", user.ID, workspace.ID, event)
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	bootstrapMeta, err := m.newEventMeta(EventBootstrapCompleted, "auth.bootstrap", user.ID, workspace.ID, event)
	if err != nil {
		return Authentication{}, Workspace{}, err
	}
	userChange := UserCreateChange{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	workspaceChange := WorkspaceCreateChange{EventMeta: workspaceMeta, Workspace: workspace, Owner: membership}
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "user.create", func(hook TransactionHook) error {
			return hook.ApplyUserCreate(ctx, tx, userChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "workspace.create", func(hook TransactionHook) error {
			return hook.ApplyWorkspaceCreate(ctx, tx, workspaceChange)
		})
	}}
	if err := m.store.Bootstrap(ctx, user, primaryEmail, PasswordCredential{UserID: user.ID, Hash: hash, UpdatedAt: now}, workspace, membership, instanceAdmin, commit); err != nil {
		return Authentication{}, Workspace{}, m.mapStoreError(ctx, "auth.bootstrap", err)
	}
	userEvent := UserCreatedEvent{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	workspaceEvent := WorkspaceCreatedEvent{EventMeta: workspaceMeta, Workspace: workspace, Owner: membership}
	bootstrapEvent := BootstrapCompletedEvent{EventMeta: bootstrapMeta, User: user, Workspace: workspace}
	m.events.emit(ctx, EventUserCreated, func(listener EventListener) error { return listener.OnUserCreated(ctx, userEvent) })
	m.events.emit(ctx, EventWorkspaceCreated, func(listener EventListener) error { return listener.OnWorkspaceCreated(ctx, workspaceEvent) })
	m.events.emit(ctx, EventBootstrapCompleted, func(listener EventListener) error { return listener.OnBootstrapCompleted(ctx, bootstrapEvent) })
	return Authentication{UserID: user.ID, Method: MethodPassword, Level: AAL1, AuthenticatedAt: now}, workspace, nil
}

func (m *Manager) CreateUser(ctx context.Context, actor Authentication, workspaceID string, input CreateUserInput) (_ User, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.user.create", started, err) }()
	if err := m.requireStepUp(ctx, actor, "auth.user.create"); err != nil {
		return User{}, err
	}
	if err := m.AuthorizePermission(ctx, actor, workspaceID, PermissionWorkspaceUsersWrite); err != nil {
		return User{}, err
	}
	email, err := validEmail(input.Email)
	if err != nil {
		return User{}, err
	}
	if strings.TrimSpace(input.DisplayName) == "" {
		return User{}, fmt.Errorf("%w: display name is required", ErrInvalidInput)
	}
	role, err := m.workspaceRoles.normalize(input.Role)
	if err != nil {
		return User{}, err
	}
	if err := m.validatePassword(input.Password); err != nil {
		return User{}, err
	}
	hash, err := m.passwords.Hash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	id, err := m.newID()
	if err != nil {
		return User{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return User{}, err
	}
	now := m.now()
	user := User{ID: id, Email: email, DisplayName: strings.TrimSpace(input.DisplayName), CreatedAt: now, UpdatedAt: now}
	primaryEmail := EmailAddress{ID: emailID, UserID: id, Address: email, Primary: true, VerifiedAt: cloneTime(&now), CreatedAt: now, UpdatedAt: now}
	membership := Membership{WorkspaceID: workspaceID, UserID: id, Role: role, Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now}
	event, err := m.newAudit(ctx, actor.UserID, "user.create", "user", id, workspaceID, AuditSucceeded, "")
	if err != nil {
		return User{}, err
	}
	meta, err := m.newEventMeta(EventUserCreated, "auth.user.create", actor.UserID, workspaceID, event)
	if err != nil {
		return User{}, err
	}
	change := UserCreateChange{EventMeta: meta, User: user, Email: primaryEmail, Membership: membership}
	commit := m.transactionalCommit(event, "user.create", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyUserCreate(ctx, tx, change)
	})
	if err := m.store.CreateUser(ctx, user, primaryEmail, PasswordCredential{UserID: id, Hash: hash, UpdatedAt: now}, membership, commit); err != nil {
		return User{}, m.mapStoreError(ctx, "auth.user.create", err)
	}
	created := UserCreatedEvent{EventMeta: meta, User: user, Email: primaryEmail, Membership: membership}
	m.events.emit(ctx, EventUserCreated, func(listener EventListener) error { return listener.OnUserCreated(ctx, created) })
	return user, nil
}

func (m *Manager) AuthenticatePassword(ctx context.Context, email, password string) (_ Authentication, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.password.authenticate", started, err) }()

	normalized := normalizeEmail(email)
	user, lookupErr := m.store.UserByEmail(ctx, normalized)
	hash := m.dummyHash
	infrastructureErr := error(nil)
	var throttle LoginThrottle
	if lookupErr == nil {
		credential, credentialErr := m.store.PasswordByUserID(ctx, user.ID)
		if credentialErr != nil {
			infrastructureErr = credentialErr
		} else {
			hash = credential.Hash
		}
		if m.maxFailedLogins > 0 && infrastructureErr == nil {
			currentThrottle, throttleErr := m.store.LoginThrottleByUserID(ctx, user.ID)
			if throttleErr == nil {
				throttle = currentThrottle
			} else if !errors.Is(throttleErr, ErrNotFound) {
				infrastructureErr = throttleErr
			}
		}
	} else if !errors.Is(lookupErr, ErrNotFound) {
		infrastructureErr = lookupErr
	}
	// The hash verification always runs, even for unknown or locked
	// accounts, so the response time never reveals whether they exist.
	match, rehash, verifyErr := m.passwords.Verify(password, hash)
	if verifyErr != nil {
		return Authentication{}, fmt.Errorf("verify password: %w", verifyErr)
	}
	if infrastructureErr != nil {
		return Authentication{}, infrastructureErr
	}
	if throttle.LockedUntil != nil && m.now().Before(*throttle.LockedUntil) {
		audit, auditErr := m.recordAuthenticationAudit(ctx, user.ID, "auth.password", AuditFailed, "locked")
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.password.authenticate", audit, MethodPassword, user.ID, "locked")
		return Authentication{}, ErrLocked
	}
	if lookupErr != nil || !match || user.Disabled {
		countFailure := lookupErr == nil && !user.Disabled && !match
		audit, auditErr := m.recordAuthenticationFailure(ctx, user.ID, "auth.password", countFailure)
		if auditErr != nil {
			return Authentication{}, auditErr
		}
		m.emitAuthenticationFailed(ctx, "auth.password.authenticate", audit, MethodPassword, user.ID, "invalid_credentials")
		return Authentication{}, ErrInvalidCredentials
	}
	if rehash {
		newHash, hashErr := m.passwords.Hash(password)
		if hashErr != nil {
			return Authentication{}, fmt.Errorf("rehash password: %w", hashErr)
		}
		event, eventErr := m.newAudit(ctx, user.ID, "password.rehash", "user", user.ID, "", AuditSucceeded, "")
		if eventErr != nil {
			return Authentication{}, eventErr
		}
		meta, metaErr := m.newEventMeta(EventPasswordRehashed, "auth.password.authenticate", user.ID, "", event)
		if metaErr != nil {
			return Authentication{}, metaErr
		}
		if replaceErr := m.store.ReplacePassword(ctx, PasswordCredential{UserID: user.ID, Hash: newHash, UpdatedAt: m.now()}, Commit{Audit: event}); replaceErr != nil {
			return Authentication{}, m.mapStoreError(ctx, "auth.password.rehash", replaceErr)
		}
		rehashed := PasswordRehashedEvent{EventMeta: meta, UserID: user.ID}
		m.events.emit(ctx, EventPasswordRehashed, func(listener EventListener) error { return listener.OnPasswordRehashed(ctx, rehashed) })
	}
	factor, factorErr := m.store.TOTPByUserID(ctx, user.ID)
	requiresSecondFactor := factorErr == nil && factor.Active
	if factorErr != nil && !errors.Is(factorErr, ErrNotFound) {
		return Authentication{}, factorErr
	}
	audit, auditErr := m.recordAuthenticationAudit(ctx, user.ID, "auth.password", AuditSucceeded, "")
	if auditErr != nil {
		return Authentication{}, auditErr
	}
	authentication := Authentication{
		UserID:               user.ID,
		Method:               MethodPassword,
		Level:                AAL1,
		AuthenticatedAt:      m.now(),
		SecondFactorRequired: requiresSecondFactor,
	}
	m.emitAuthenticationSucceeded(ctx, "auth.password.authenticate", audit, authentication)
	return authentication, nil
}

func (m *Manager) ChangePassword(ctx context.Context, actor Authentication, currentPassword, newPassword string) (err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.password.change", started, err) }()
	if err := m.requireRecentInteractive(ctx, actor); err != nil {
		return err
	}
	if err := m.validatePassword(newPassword); err != nil {
		return err
	}
	credential, err := m.store.PasswordByUserID(ctx, actor.UserID)
	if err != nil {
		return ErrInvalidCredentials
	}
	match, _, err := m.passwords.Verify(currentPassword, credential.Hash)
	if err != nil {
		return fmt.Errorf("verify password: %w", err)
	}
	if !match {
		if auditErr := m.appendAuthenticationAudit(ctx, actor.UserID, "password.change", AuditFailed, "invalid_credentials"); auditErr != nil {
			return auditErr
		}
		return ErrInvalidCredentials
	}
	hash, err := m.passwords.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	event, err := m.newAudit(ctx, actor.UserID, "password.change", "user", actor.UserID, "", AuditSucceeded, "")
	if err != nil {
		return err
	}
	meta, err := m.newEventMeta(EventPasswordChanged, "auth.password.change", actor.UserID, "", event)
	if err != nil {
		return err
	}
	change := PasswordChange{EventMeta: meta, UserID: actor.UserID}
	commit := m.transactionalCommit(event, "password.change", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyPasswordChange(ctx, tx, change)
	})
	if err := m.store.ReplacePassword(ctx, PasswordCredential{UserID: actor.UserID, Hash: hash, UpdatedAt: m.now()}, commit); err != nil {
		return m.mapStoreError(ctx, "auth.password.change", err)
	}
	changed := PasswordChangedEvent{EventMeta: meta, UserID: actor.UserID}
	m.events.emit(ctx, EventPasswordChanged, func(listener EventListener) error { return listener.OnPasswordChanged(ctx, changed) })
	return nil
}

func (m *Manager) RequireStepUp(authn Authentication) error {
	if authn.UserID == "" {
		return ErrUnauthorized
	}
	age := m.now().Sub(authn.AuthenticatedAt)
	if !authn.Interactive() || authn.Level < AAL2 || age < 0 || age > m.stepUpMaxAge {
		return ErrStepUpRequired
	}
	return nil
}

func (m *Manager) requireStepUp(ctx context.Context, authn Authentication, operation string) error {
	err := m.RequireStepUp(authn)
	if err == nil {
		return m.requireActiveUser(ctx, authn.UserID)
	}
	if !errors.Is(err, ErrStepUpRequired) {
		return err
	}
	meta, metaErr := m.newEventMeta(EventStepUpDenied, operation, authn.UserID, authn.WorkspaceID, AuditEvent{})
	if metaErr == nil {
		event := StepUpDeniedEvent{EventMeta: meta, UserID: authn.UserID}
		m.events.emit(ctx, EventStepUpDenied, func(listener EventListener) error {
			return listener.OnStepUpDenied(ctx, event)
		})
	}
	return err
}

func (m *Manager) requireRecentInteractive(ctx context.Context, authn Authentication) error {
	if authn.UserID == "" {
		return ErrUnauthorized
	}
	age := m.now().Sub(authn.AuthenticatedAt)
	if !authn.Interactive() || age < 0 || age > m.stepUpMaxAge {
		return ErrStepUpRequired
	}
	return m.requireActiveUser(ctx, authn.UserID)
}

func (m *Manager) requireActiveUser(ctx context.Context, userID string) error {
	user, err := m.store.UserByID(ctx, userID)
	if err != nil {
		// An Authentication is an authorization capability, not a lookup API.
		// Do not reveal whether its user disappeared or storage failed while
		// evaluating the capability.
		return ErrForbidden
	}
	if user.Disabled {
		return ErrForbidden
	}
	return nil
}

func (m *Manager) validatePassword(password string) error {
	length := len([]rune(password))
	if length < m.minPasswordLen {
		return fmt.Errorf("%w: password must contain at least %d characters", ErrInvalidInput, m.minPasswordLen)
	}
	if length > 1024 {
		return fmt.Errorf("%w: password cannot exceed 1024 characters", ErrInvalidInput)
	}
	return nil
}

func validEmail(value string) (string, error) {
	normalized := normalizeEmail(value)
	parsed, err := mail.ParseAddress(normalized)
	if err != nil || parsed.Address != normalized || len(normalized) > 320 {
		return "", fmt.Errorf("%w: invalid email", ErrInvalidInput)
	}
	return normalized, nil
}

func (m *Manager) newAudit(ctx context.Context, actor, action, resourceType, resourceID, workspaceID string, outcome AuditOutcome, reason string) (AuditEvent, error) {
	id, err := m.newID()
	if err != nil {
		return AuditEvent{}, err
	}
	metadata := requestMetadataFromContext(ctx)
	// Timestamps are truncated to microseconds so the audit hash chain
	// recomputes identically after a PostgreSQL round trip.
	return AuditEvent{
		ID: id, OccurredAt: m.now().Truncate(time.Microsecond), ActorKind: ActorUser, ActorID: actor, Action: action,
		ResourceType: resourceType, ResourceID: resourceID, WorkspaceID: workspaceID,
		Outcome: outcome, Reason: reason,
		IPAddress: metadata.IPAddress, UserAgent: metadata.UserAgent,
	}, nil
}

func (m *Manager) recordAuthenticationAudit(ctx context.Context, actor, action string, outcome AuditOutcome, reason string) (AuditEvent, error) {
	event, err := m.newAudit(ctx, actor, action, "user", actor, "", outcome, reason)
	if err != nil {
		return AuditEvent{}, err
	}
	var storeErr error
	if outcome == AuditSucceeded && actor != "" {
		storeErr = m.store.RecordAuthentication(ctx, actor, m.now(), Commit{Audit: event})
	} else {
		storeErr = m.store.AppendAudit(ctx, Commit{Audit: event})
	}
	if storeErr != nil {
		return AuditEvent{}, m.mapStoreError(ctx, action, storeErr)
	}
	return event, nil
}

func (m *Manager) appendAuthenticationAudit(ctx context.Context, actor, action string, outcome AuditOutcome, reason string) error {
	_, err := m.recordAuthenticationAudit(ctx, actor, action, outcome, reason)
	return err
}

// recordAuthenticationFailure audits a failed credential check and, when the
// failure is attributable to an existing enabled account, counts it toward
// the lockout threshold within the same transaction.
func (m *Manager) recordAuthenticationFailure(ctx context.Context, userID, action string, countFailure bool) (AuditEvent, error) {
	if !countFailure || m.maxFailedLogins <= 0 {
		return m.recordAuthenticationAudit(ctx, userID, action, AuditFailed, "invalid_credentials")
	}
	event, err := m.newAudit(ctx, userID, action, "user", userID, "", AuditFailed, "invalid_credentials")
	if err != nil {
		return AuditEvent{}, err
	}
	throttle, err := m.store.RecordLoginFailure(ctx, userID, m.now(), m.maxFailedLogins, m.now().Add(m.lockoutDuration), Commit{Audit: event})
	if err != nil {
		return AuditEvent{}, m.mapStoreError(ctx, action, err)
	}
	if throttle.LockedUntil != nil && throttle.FailedAttempts == m.maxFailedLogins {
		if meta, metaErr := m.newEventMeta(EventUserLocked, action, userID, "", event); metaErr == nil {
			locked := UserLockedEvent{EventMeta: meta, UserID: userID, LockedUntil: *throttle.LockedUntil}
			m.events.emit(ctx, EventUserLocked, func(listener EventListener) error { return listener.OnUserLocked(ctx, locked) })
		}
	}
	return event, nil
}

// requireUnlocked rejects a second-factor attempt while the account lockout
// is active.
func (m *Manager) requireUnlocked(ctx context.Context, userID, action string) error {
	if m.maxFailedLogins <= 0 {
		return nil
	}
	throttle, err := m.store.LoginThrottleByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	if throttle.LockedUntil != nil && m.now().Before(*throttle.LockedUntil) {
		if auditErr := m.appendAuthenticationAudit(ctx, userID, action, AuditFailed, "locked"); auditErr != nil {
			return auditErr
		}
		return ErrLocked
	}
	return nil
}

func mapAuditError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAuditUnavailable) {
		return ErrAuditUnavailable
	}
	return err
}
