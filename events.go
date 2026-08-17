package credbound

//go:generate go run ./internal/cmd/genevents

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type StoreKind string

const (
	StoreMemory     StoreKind = "memory"
	StoreSQLite     StoreKind = "sqlite"
	StorePostgreSQL StoreKind = "postgresql"
)

// Tx represents the store transaction that is open during a TransactionHook.
// It is only valid for the duration of the callback and must not be retained or
// used by another goroutine.
type Tx interface {
	Kind() StoreKind
	Audit() AuditEvent
}

// Commit couples the mandatory audit with an optional extension of the same
// store transaction. Store implementations must commit all three stages
// (mutation, Transactional callback and audit) or none of them.
type Commit struct {
	Audit         AuditEvent
	Transactional func(context.Context, Tx) error
}

type EventName string

const (
	EventBootstrapCompleted           EventName = "bootstrap.completed"
	EventUserCreated                  EventName = "user.created"
	EventUserDisabled                 EventName = "user.disabled"
	EventUserEnabled                  EventName = "user.enabled"
	EventWorkspaceCreated             EventName = "workspace.created"
	EventWorkspaceUpdated             EventName = "workspace.updated"
	EventWorkspaceDisabled            EventName = "workspace.disabled"
	EventWorkspaceEnabled             EventName = "workspace.enabled"
	EventMembershipAdded              EventName = "membership.added"
	EventWorkspaceInvitationCreated   EventName = "workspace.invitation_created"
	EventWorkspaceInvitationAccepted  EventName = "workspace.invitation_accepted"
	EventWorkspaceInvitationRevoked   EventName = "workspace.invitation_revoked"
	EventMembershipStatusChanged      EventName = "membership.status_changed"
	EventMembershipRemoved            EventName = "membership.removed"
	EventPasswordChanged              EventName = "password.changed"
	EventPasswordRehashed             EventName = "password.rehashed"
	EventPasswordResetRequested       EventName = "password.reset_requested"
	EventPasswordResetCompleted       EventName = "password.reset_completed"
	EventEmailAuthenticationRequested EventName = "email_authentication.requested"
	EventAuthenticationSucceeded      EventName = "authentication.succeeded"
	EventAuthenticationFailed         EventName = "authentication.failed"
	EventStepUpDenied                 EventName = "step_up.denied"
	EventAuthorizationDenied          EventName = "authorization.denied"
	EventEmailAdded                   EventName = "email.added"
	EventEmailConfirmed               EventName = "email.confirmed"
	EventPrimaryEmailChanged          EventName = "email.primary_changed"
	EventEmailRemoved                 EventName = "email.removed"
	EventTOTPEnrollmentStarted        EventName = "totp.enrollment_started"
	EventTOTPActivated                EventName = "totp.activated"
	EventTOTPDisabled                 EventName = "totp.disabled"
	EventTOTPVerified                 EventName = "totp.verified"
	EventTOTPReplayRejected           EventName = "totp.replay_rejected"
	EventRecoveryCodeConsumed         EventName = "recovery_code.consumed"
	EventPasskeyRegistered            EventName = "passkey.registered"
	EventPasskeyDeleted               EventName = "passkey.deleted"
	EventPasskeyAuthenticated         EventName = "passkey.authenticated"
	EventUserCredentialsRevoked       EventName = "user.credentials_revoked"
	EventUserLocked                   EventName = "user.locked"
	EventPATCreated                   EventName = "pat.created"
	EventPATRevoked                   EventName = "pat.revoked"
	EventPATAuthenticated             EventName = "pat.authenticated"
	EventPATRejected                  EventName = "pat.rejected"
	EventSSOChallengeIssued           EventName = "sso.challenge_issued"
	EventSSOLinked                    EventName = "sso.linked"
	EventSSOUnlinked                  EventName = "sso.unlinked"
	EventSSOAuthenticated             EventName = "sso.authenticated"
	EventRoleGranted                  EventName = "role.granted"
	EventInstanceRoleChanged          EventName = "instance_role.changed"
	EventInstanceRoleRemoved          EventName = "instance_role.removed"
	EventClientAuditRecorded          EventName = "client_audit.recorded"
	EventAuditUnavailable             EventName = "audit.unavailable"
	EventSCIMConfigurationCreated     EventName = "scim.configuration.created"
	EventSCIMUserProvisioned          EventName = "scim.user.provisioned"
	EventSCIMUserUpdated              EventName = "scim.user.updated"
	EventSCIMUserActivated            EventName = "scim.user.activated"
	EventSCIMUserSuspended            EventName = "scim.user.suspended"
	EventSCIMUserDeprovisioned        EventName = "scim.user.deprovisioned"
	EventSCIMGroupCreated             EventName = "scim.group.created"
	EventSCIMGroupUpdated             EventName = "scim.group.updated"
	EventSCIMGroupDeleted             EventName = "scim.group.deleted"
	EventSCIMGroupMembersChanged      EventName = "scim.group.members_changed"
	EventOAuthClientRegistered        EventName = "oauth.client.registered"
	EventOAuthClientDisabled          EventName = "oauth.client.disabled"
	EventOAuthClientEnabled           EventName = "oauth.client.enabled"
	EventOAuthIssuerDisabled          EventName = "oauth.issuer.disabled"
	EventOAuthIssuerEnabled           EventName = "oauth.issuer.enabled"
	EventOAuthResourceDisabled        EventName = "oauth.resource.disabled"
	EventOAuthResourceEnabled         EventName = "oauth.resource.enabled"
	EventOAuthCIMDResolved            EventName = "oauth.cimd.resolved"
	EventOAuthCIMDRejected            EventName = "oauth.cimd.rejected"
	EventOAuthCIMDChanged             EventName = "oauth.cimd.changed"
	EventOAuthAuthorizationGranted    EventName = "oauth.authorization.granted"
	EventOAuthAuthorizationDenied     EventName = "oauth.authorization.denied"
	EventOAuthTokenIssued             EventName = "oauth.token.issued"
	EventOAuthTokenRefreshed          EventName = "oauth.token.refreshed"
	EventOAuthTokenRevoked            EventName = "oauth.token.revoked"
	EventOAuthRefreshReuseDetected    EventName = "oauth.refresh_token.reuse_detected"
	EventOAuthConsentRevoked          EventName = "oauth.consent.revoked"
)

type EventMeta struct {
	ID          string
	Name        EventName
	Operation   string
	OccurredAt  time.Time
	ActorID     string
	WorkspaceID string
	AuditID     string
}

// Transaction payloads deliberately contain no passwords, credential hashes,
// verification tokens, raw PATs, TOTP secrets, recovery codes or SSO tokens.
type UserCreateChange struct {
	EventMeta
	User       User
	Email      EmailAddress
	Membership Membership
}

type WorkspaceCreateChange struct {
	EventMeta
	Workspace Workspace
	Owner     Membership
}

type UserStatusChange struct {
	EventMeta
	UserID   string
	Disabled bool
}

type WorkspaceChange struct {
	EventMeta
	Workspace Workspace
	Previous  Workspace
}

type MembershipChange struct {
	EventMeta
	Membership Membership
	Previous   *Membership
	Removed    bool
}

// WorkspaceInvitationChange never carries the invitation digest.
type WorkspaceInvitationChange struct {
	EventMeta
	Invitation WorkspaceInvitation
}

type PasswordChange struct {
	EventMeta
	UserID string
}

type EmailAddition struct {
	EventMeta
	Email EmailAddress
}

type EmailConfirmation struct {
	EventMeta
	Email EmailAddress
}

type PrimaryEmailChange struct {
	EventMeta
	UserID  string
	EmailID string
}

type EmailRemoval struct {
	EventMeta
	UserID  string
	EmailID string
}

type TOTPEnrollmentChange struct {
	EventMeta
	UserID string
}

type TOTPActivation struct {
	EventMeta
	UserID            string
	RecoveryCodeCount int
}

type TOTPDisable struct {
	EventMeta
	UserID string
}

type PasskeyRegistration struct {
	EventMeta
	PasskeyID   string
	UserID      string
	PasskeyName string
}

type PasskeyDeletion struct {
	EventMeta
	PasskeyID string
	UserID    string
}

type PATCreation struct {
	EventMeta
	PATID            string
	UserID           string
	PATName          string
	BoundWorkspaceID string
	Scopes           []string
	ExpiresAt        *time.Time
}

type PATRevocation struct {
	EventMeta
	PATID  string
	UserID string
}

type UserCredentialRevocation struct {
	EventMeta
	UserID string
}

type SSOLink struct {
	EventMeta
	Identity SSOIdentity
}

type SSOUnlink struct {
	EventMeta
	UserID     string
	IdentityID string
}

type RoleGrant struct {
	EventMeta
	UserID       string
	Role         Role
	PreviousRole Role
}

type InstanceRoleChange struct {
	EventMeta
	UserID       string
	Role         InstanceRole
	PreviousRole InstanceRole
}

type InstanceRoleRemoval struct {
	EventMeta
	UserID       string
	PreviousRole InstanceRole
}

type ClientAuditRecord struct {
	EventMeta
	Audit AuditEvent
}

type SCIMConfigurationChange struct {
	EventMeta
	Configuration SCIMConfiguration
}

type SCIMUserChange struct {
	EventMeta
	User SCIMUser
}

type SCIMGroupChange struct {
	EventMeta
	Group SCIMGroup
}

type OAuthChange struct {
	EventMeta
	IssuerID     string
	ClientID     string
	ClientSource OAuthClientSource
	GrantID      string
	TokenID      string
	ResourceID   string
	Scopes       []string
}

type BootstrapCompletedEvent struct {
	EventMeta
	User      User
	Workspace Workspace
}

type UserCreatedEvent struct {
	EventMeta
	User       User
	Email      EmailAddress
	Membership Membership
}

type WorkspaceCreatedEvent struct {
	EventMeta
	Workspace Workspace
	Owner     Membership
}

type PasswordChangedEvent struct {
	EventMeta
	UserID string
}

type PasswordRehashedEvent struct {
	EventMeta
	UserID string
}

type AuthenticationEvent struct {
	EventMeta
	Authentication Authentication
}

type AuthenticationFailureEvent struct {
	EventMeta
	Method AuthMethod
	UserID string
	Reason string
}

type StepUpDeniedEvent struct {
	EventMeta
	UserID string
}

type AuthorizationDeniedEvent struct {
	EventMeta
	UserID       string
	RequiredRole Role
}

type EmailAddedEvent struct {
	EventMeta
	Email EmailAddress
}

type EmailConfirmedEvent struct {
	EventMeta
	Email EmailAddress
}

type PrimaryEmailChangedEvent struct {
	EventMeta
	UserID  string
	EmailID string
}

type EmailRemovedEvent struct {
	EventMeta
	UserID  string
	EmailID string
}

type TOTPEnrollmentStartedEvent struct {
	EventMeta
	UserID string
}

type TOTPActivatedEvent struct {
	EventMeta
	UserID            string
	RecoveryCodeCount int
}

type TOTPDisabledEvent struct {
	EventMeta
	UserID string
}

type TOTPVerifiedEvent struct {
	EventMeta
	UserID string
}

type TOTPReplayRejectedEvent struct {
	EventMeta
	UserID string
}

type RecoveryCodeConsumedEvent struct {
	EventMeta
	UserID string
}

type PasskeyRegisteredEvent struct {
	EventMeta
	PasskeyID   string
	UserID      string
	PasskeyName string
}

type PasskeyDeletedEvent struct {
	EventMeta
	PasskeyID string
	UserID    string
}

type PasskeyAuthenticatedEvent struct {
	EventMeta
	PasskeyID string
	UserID    string
}

type PATCreatedEvent struct {
	EventMeta
	PATID            string
	UserID           string
	PATName          string
	BoundWorkspaceID string
	Scopes           []string
	ExpiresAt        *time.Time
}

type PATRevokedEvent struct {
	EventMeta
	PATID  string
	UserID string
}

type UserCredentialsRevokedEvent struct {
	EventMeta
	UserID string
}

type UserLockedEvent struct {
	EventMeta
	UserID      string
	LockedUntil time.Time
}

type PasswordResetRequestedEvent struct {
	EventMeta
	UserID    string
	ResetID   string
	ExpiresAt time.Time
}

type PasswordResetCompletedEvent struct {
	EventMeta
	UserID string
}

type EmailAuthenticationRequestedEvent struct {
	EventMeta
	UserID    string
	EmailID   string
	ExpiresAt time.Time
}

type PATAuthenticatedEvent struct {
	EventMeta
	PATID  string
	UserID string
}

type PATRejectedEvent struct {
	EventMeta
	Reason string
}

type SSOChallengeIssuedEvent struct {
	EventMeta
	ProviderConfigurationID string
	ProviderKind            SSOProviderKind
	Purpose                 string
}

type SSOLinkedEvent struct {
	EventMeta
	Identity SSOIdentity
}

type SSOUnlinkedEvent struct {
	EventMeta
	UserID     string
	IdentityID string
}

type SSOAuthenticatedEvent struct {
	EventMeta
	IdentityID     string
	Authentication Authentication
}

type RoleGrantedEvent struct {
	EventMeta
	UserID       string
	Role         Role
	PreviousRole Role
}

type InstanceRoleChangedEvent struct {
	EventMeta
	UserID       string
	Role         InstanceRole
	PreviousRole InstanceRole
}

type InstanceRoleRemovedEvent struct {
	EventMeta
	UserID       string
	PreviousRole InstanceRole
}

type ClientAuditRecordedEvent struct {
	EventMeta
	Audit AuditEvent
}

type AuditUnavailableEvent struct {
	EventMeta
	FailedOperation string
}

type SCIMConfigurationCreatedEvent struct {
	EventMeta
	Configuration SCIMConfiguration
}

type SCIMUserEvent struct {
	EventMeta
	User SCIMUser
}

type SCIMGroupEvent struct {
	EventMeta
	Group SCIMGroup
}

type OAuthEvent struct {
	OAuthChange
}

type UserStatusEvent struct {
	EventMeta
	UserID   string
	Disabled bool
}

type WorkspaceChangedEvent struct {
	EventMeta
	Workspace Workspace
	Previous  Workspace
}

type MembershipChangedEvent struct {
	EventMeta
	Membership Membership
	Previous   *Membership
	Removed    bool
}

// WorkspaceInvitationEvent never carries the invitation digest.
type WorkspaceInvitationEvent struct {
	EventMeta
	Invitation WorkspaceInvitation
}

type TransactionHook interface {
	unimplementedTransactionHook()

	ApplyUserCreate(context.Context, Tx, UserCreateChange) error
	ApplyWorkspaceCreate(context.Context, Tx, WorkspaceCreateChange) error
	ApplyUserStatusChange(context.Context, Tx, UserStatusChange) error
	ApplyWorkspaceChange(context.Context, Tx, WorkspaceChange) error
	ApplyMembershipChange(context.Context, Tx, MembershipChange) error
	ApplyWorkspaceInvitationChange(context.Context, Tx, WorkspaceInvitationChange) error
	ApplyPasswordChange(context.Context, Tx, PasswordChange) error
	ApplyEmailAddition(context.Context, Tx, EmailAddition) error
	ApplyEmailConfirmation(context.Context, Tx, EmailConfirmation) error
	ApplyPrimaryEmailChange(context.Context, Tx, PrimaryEmailChange) error
	ApplyEmailRemoval(context.Context, Tx, EmailRemoval) error
	ApplyTOTPEnrollment(context.Context, Tx, TOTPEnrollmentChange) error
	ApplyTOTPActivation(context.Context, Tx, TOTPActivation) error
	ApplyTOTPDisable(context.Context, Tx, TOTPDisable) error
	ApplyPasskeyRegistration(context.Context, Tx, PasskeyRegistration) error
	ApplyPasskeyDeletion(context.Context, Tx, PasskeyDeletion) error
	ApplyPATCreation(context.Context, Tx, PATCreation) error
	ApplyPATRevocation(context.Context, Tx, PATRevocation) error
	ApplyUserCredentialRevocation(context.Context, Tx, UserCredentialRevocation) error
	ApplySSOLink(context.Context, Tx, SSOLink) error
	ApplySSOUnlink(context.Context, Tx, SSOUnlink) error
	ApplyRoleGrant(context.Context, Tx, RoleGrant) error
	ApplyInstanceRoleChange(context.Context, Tx, InstanceRoleChange) error
	ApplyInstanceRoleRemoval(context.Context, Tx, InstanceRoleRemoval) error
	ApplyClientAudit(context.Context, Tx, ClientAuditRecord) error
	ApplySCIMConfigurationCreate(context.Context, Tx, SCIMConfigurationChange) error
	ApplySCIMUserProvision(context.Context, Tx, SCIMUserChange) error
	ApplySCIMUserUpdate(context.Context, Tx, SCIMUserChange) error
	ApplySCIMUserDeprovision(context.Context, Tx, SCIMUserChange) error
	ApplySCIMGroupUpsert(context.Context, Tx, SCIMGroupChange) error
	ApplySCIMGroupDelete(context.Context, Tx, SCIMGroupChange) error
	ApplyOAuthChange(context.Context, Tx, OAuthChange) error
}

type EventListener interface {
	unimplementedEventListener()

	OnBootstrapCompleted(context.Context, BootstrapCompletedEvent) error
	OnUserCreated(context.Context, UserCreatedEvent) error
	OnWorkspaceCreated(context.Context, WorkspaceCreatedEvent) error
	OnUserStatusChanged(context.Context, UserStatusEvent) error
	OnWorkspaceChanged(context.Context, WorkspaceChangedEvent) error
	OnMembershipChanged(context.Context, MembershipChangedEvent) error
	OnWorkspaceInvitationCreated(context.Context, WorkspaceInvitationEvent) error
	OnWorkspaceInvitationAccepted(context.Context, WorkspaceInvitationEvent) error
	OnWorkspaceInvitationRevoked(context.Context, WorkspaceInvitationEvent) error
	OnPasswordChanged(context.Context, PasswordChangedEvent) error
	OnPasswordRehashed(context.Context, PasswordRehashedEvent) error
	OnAuthenticationSucceeded(context.Context, AuthenticationEvent) error
	OnAuthenticationFailed(context.Context, AuthenticationFailureEvent) error
	OnStepUpDenied(context.Context, StepUpDeniedEvent) error
	OnAuthorizationDenied(context.Context, AuthorizationDeniedEvent) error
	OnEmailAdded(context.Context, EmailAddedEvent) error
	OnEmailConfirmed(context.Context, EmailConfirmedEvent) error
	OnPrimaryEmailChanged(context.Context, PrimaryEmailChangedEvent) error
	OnEmailRemoved(context.Context, EmailRemovedEvent) error
	OnTOTPEnrollmentStarted(context.Context, TOTPEnrollmentStartedEvent) error
	OnTOTPActivated(context.Context, TOTPActivatedEvent) error
	OnTOTPDisabled(context.Context, TOTPDisabledEvent) error
	OnTOTPVerified(context.Context, TOTPVerifiedEvent) error
	OnTOTPReplayRejected(context.Context, TOTPReplayRejectedEvent) error
	OnRecoveryCodeConsumed(context.Context, RecoveryCodeConsumedEvent) error
	OnPasskeyRegistered(context.Context, PasskeyRegisteredEvent) error
	OnPasskeyDeleted(context.Context, PasskeyDeletedEvent) error
	OnPasskeyAuthenticated(context.Context, PasskeyAuthenticatedEvent) error
	OnPATCreated(context.Context, PATCreatedEvent) error
	OnPATRevoked(context.Context, PATRevokedEvent) error
	OnUserCredentialsRevoked(context.Context, UserCredentialsRevokedEvent) error
	OnUserLocked(context.Context, UserLockedEvent) error
	OnPasswordResetRequested(context.Context, PasswordResetRequestedEvent) error
	OnPasswordResetCompleted(context.Context, PasswordResetCompletedEvent) error
	OnEmailAuthenticationRequested(context.Context, EmailAuthenticationRequestedEvent) error
	OnPATAuthenticated(context.Context, PATAuthenticatedEvent) error
	OnPATRejected(context.Context, PATRejectedEvent) error
	OnSSOChallengeIssued(context.Context, SSOChallengeIssuedEvent) error
	OnSSOLinked(context.Context, SSOLinkedEvent) error
	OnSSOUnlinked(context.Context, SSOUnlinkedEvent) error
	OnSSOAuthenticated(context.Context, SSOAuthenticatedEvent) error
	OnRoleGranted(context.Context, RoleGrantedEvent) error
	OnInstanceRoleChanged(context.Context, InstanceRoleChangedEvent) error
	OnInstanceRoleRemoved(context.Context, InstanceRoleRemovedEvent) error
	OnClientAuditRecorded(context.Context, ClientAuditRecordedEvent) error
	OnAuditUnavailable(context.Context, AuditUnavailableEvent) error
	OnSCIMConfigurationCreated(context.Context, SCIMConfigurationCreatedEvent) error
	OnSCIMUserProvisioned(context.Context, SCIMUserEvent) error
	OnSCIMUserUpdated(context.Context, SCIMUserEvent) error
	OnSCIMUserActivated(context.Context, SCIMUserEvent) error
	OnSCIMUserSuspended(context.Context, SCIMUserEvent) error
	OnSCIMUserDeprovisioned(context.Context, SCIMUserEvent) error
	OnSCIMGroupCreated(context.Context, SCIMGroupEvent) error
	OnSCIMGroupUpdated(context.Context, SCIMGroupEvent) error
	OnSCIMGroupDeleted(context.Context, SCIMGroupEvent) error
	OnSCIMGroupMembersChanged(context.Context, SCIMGroupEvent) error
	OnOAuthEvent(context.Context, OAuthEvent) error
}

type Subscription interface {
	Remove()
}

type registeredTransactionHook struct {
	id   uint64
	hook TransactionHook
}

type registeredEventListener struct {
	id       uint64
	listener EventListener
}

type eventRegistry struct {
	mu        sync.RWMutex
	nextID    atomic.Uint64
	hooks     []registeredTransactionHook
	listeners []registeredEventListener
	observer  Observer
	now       func() time.Time
}

type eventSubscription struct {
	once   sync.Once
	remove func()
}

func (s *eventSubscription) Remove() {
	if s == nil {
		return
	}
	s.once.Do(s.remove)
}

func newEventRegistry(observer Observer, now func() time.Time, hooks []TransactionHook, listeners []EventListener) (*eventRegistry, error) {
	registry := &eventRegistry{observer: observer, now: now}
	for _, hook := range hooks {
		if nilInterface(hook) {
			return nil, fmt.Errorf("%w: nil transaction hook", ErrInvalidInput)
		}
		registry.hooks = append(registry.hooks, registeredTransactionHook{id: registry.nextID.Add(1), hook: hook})
	}
	for _, listener := range listeners {
		if nilInterface(listener) {
			return nil, fmt.Errorf("%w: nil event listener", ErrInvalidInput)
		}
		registry.listeners = append(registry.listeners, registeredEventListener{id: registry.nextID.Add(1), listener: listener})
	}
	return registry, nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (m *Manager) AddTransactionHook(hook TransactionHook) Subscription {
	if nilInterface(hook) {
		return &eventSubscription{remove: func() {}}
	}
	return m.events.addTransactionHook(hook)
}

func (m *Manager) AddEventListener(listener EventListener) Subscription {
	if nilInterface(listener) {
		return &eventSubscription{remove: func() {}}
	}
	return m.events.addEventListener(listener)
}

func (r *eventRegistry) addTransactionHook(hook TransactionHook) Subscription {
	id := r.nextID.Add(1)
	r.mu.Lock()
	r.hooks = append(r.hooks, registeredTransactionHook{id: id, hook: hook})
	r.mu.Unlock()
	return &eventSubscription{remove: func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for index := range r.hooks {
			if r.hooks[index].id == id {
				r.hooks = slices.Delete(r.hooks, index, index+1)
				return
			}
		}
	}}
}

func (r *eventRegistry) addEventListener(listener EventListener) Subscription {
	id := r.nextID.Add(1)
	r.mu.Lock()
	r.listeners = append(r.listeners, registeredEventListener{id: id, listener: listener})
	r.mu.Unlock()
	return &eventSubscription{remove: func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for index := range r.listeners {
			if r.listeners[index].id == id {
				r.listeners = slices.Delete(r.listeners, index, index+1)
				return
			}
		}
	}}
}

func (r *eventRegistry) transactionHooks() []registeredTransactionHook {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.hooks)
}

func (r *eventRegistry) eventListeners() []registeredEventListener {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.listeners)
}

func (r *eventRegistry) apply(ctx context.Context, operation string, call func(TransactionHook) error) error {
	for _, registered := range r.transactionHooks() {
		started := r.now()
		err, panicked := safeEventCall(func() error { return call(registered.hook) })
		outcome := callbackOutcome(err, panicked)
		r.observer.Observe(ctx, Operation{Name: "transaction." + operation, Outcome: outcome, Duration: r.now().Sub(started)})
		if err != nil {
			return mapTransactionError(err)
		}
	}
	return nil
}

func (r *eventRegistry) emit(ctx context.Context, name EventName, call func(EventListener) error) {
	for _, registered := range r.eventListeners() {
		started := r.now()
		err, panicked := safeEventCall(func() error { return call(registered.listener) })
		r.observer.Observe(ctx, Operation{Name: "event." + string(name), Outcome: callbackOutcome(err, panicked), Duration: r.now().Sub(started)})
	}
}

func safeEventCall(call func() error) (err error, panicked bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("callback panic: %v", recovered)
			panicked = true
		}
	}()
	return call(), false
}

func callbackOutcome(err error, panicked bool) string {
	if panicked {
		return "panic"
	}
	if err != nil {
		return "error"
	}
	return "success"
}

func mapTransactionError(err error) error {
	if err == nil {
		return nil
	}
	for _, sentinel := range []error{
		ErrInvalidCredentials, ErrUnauthorized, ErrForbidden, ErrStepUpRequired,
		ErrConflict, ErrNotFound, ErrInvalidInput, ErrExpired, ErrAuditUnavailable,
		context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, sentinel) {
			return err
		}
	}
	return fmt.Errorf("%w: %v", ErrTransactionRejected, err)
}

func (m *Manager) newEventMeta(name EventName, operation, actorID, workspaceID string, audit AuditEvent) (EventMeta, error) {
	id, err := m.newID()
	if err != nil {
		return EventMeta{}, err
	}
	return EventMeta{
		ID: id, Name: name, Operation: operation, OccurredAt: m.now(),
		ActorID: actorID, WorkspaceID: workspaceID, AuditID: audit.ID,
	}, nil
}

func (m *Manager) transactionalCommit(audit AuditEvent, operation string, call func(context.Context, Tx, TransactionHook) error) Commit {
	return Commit{
		Audit: audit,
		Transactional: func(ctx context.Context, tx Tx) error {
			return m.events.apply(ctx, operation, func(hook TransactionHook) error {
				return call(ctx, tx, hook)
			})
		},
	}
}

func (m *Manager) mapStoreError(ctx context.Context, operation string, err error) error {
	mapped := mapAuditError(err)
	if errors.Is(mapped, ErrAuditUnavailable) {
		m.emitAuditUnavailable(ctx, operation)
	}
	return mapped
}

func (m *Manager) emitAuditUnavailable(ctx context.Context, operation string) {
	meta, err := m.newEventMeta(EventAuditUnavailable, operation, "", "", AuditEvent{})
	if err != nil {
		return
	}
	event := AuditUnavailableEvent{EventMeta: meta, FailedOperation: operation}
	m.events.emit(ctx, EventAuditUnavailable, func(listener EventListener) error {
		return listener.OnAuditUnavailable(ctx, event)
	})
}

func (m *Manager) emitAuthenticationSucceeded(ctx context.Context, operation string, audit AuditEvent, authentication Authentication) {
	meta, err := m.newEventMeta(EventAuthenticationSucceeded, operation, authentication.UserID, authentication.WorkspaceID, audit)
	if err != nil {
		return
	}
	event := AuthenticationEvent{EventMeta: meta, Authentication: cloneAuthentication(authentication)}
	m.events.emit(ctx, EventAuthenticationSucceeded, func(listener EventListener) error {
		return listener.OnAuthenticationSucceeded(ctx, event)
	})
}

func (m *Manager) emitAuthenticationFailed(ctx context.Context, operation string, audit AuditEvent, method AuthMethod, userID, reason string) {
	meta, err := m.newEventMeta(EventAuthenticationFailed, operation, userID, "", audit)
	if err != nil {
		return
	}
	event := AuthenticationFailureEvent{EventMeta: meta, Method: method, UserID: userID, Reason: reason}
	m.events.emit(ctx, EventAuthenticationFailed, func(listener EventListener) error {
		return listener.OnAuthenticationFailed(ctx, event)
	})
}

func cloneAuthentication(value Authentication) Authentication {
	value.Scopes = slices.Clone(value.Scopes)
	return value
}

func clonePATExpiration(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
