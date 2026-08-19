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

// StoreKind identifies the engine behind a Tx so a TransactionHook can
// recover the engine-specific handle (for example sqlstore's TxFrom).
type StoreKind string

const (
	StoreMemory     StoreKind = "memory"
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
	// Ceremony, when set, marks the single-use ceremony that authorized
	// this mutation as consumed in the same transaction: the store records
	// the ceremony id and fails the whole commit with ErrConflict when it
	// was already recorded, so a replayed ceremony can never commit twice.
	// Records may be pruned once ExpiresAt has passed.
	Ceremony *CeremonyConsumption
}

// CeremonyConsumption identifies a single-use ceremony continuation being
// consumed by a Commit. ID is the UUIDv7 minted when the ceremony began and
// ExpiresAt bounds how long the store must remember it.
type CeremonyConsumption struct {
	ID        string
	ExpiresAt time.Time
}

// EventName is the stable, unversioned name of an event, such as
// "user.created" or "workspace.created". Payload shapes follow the library
// version; names do not change.
type EventName string

const (
	EventBootstrapCompleted           EventName = "bootstrap.completed"
	EventSignUpCompleted              EventName = "signup.completed"
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
	EventWorkspaceDomainCreated       EventName = "workspace.domain.created"
	EventWorkspaceDomainConfirmed     EventName = "workspace.domain.confirmed"
	EventWorkspaceDomainPolicyUpdated EventName = "workspace.domain.policy_updated"
	EventWorkspaceDomainRemoved       EventName = "workspace.domain.removed"
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
	EventEmailVerificationResent      EventName = "email.verification_resent"
	EventPrimaryEmailChanged          EventName = "email.primary_changed"
	EventEmailRemoved                 EventName = "email.removed"
	EventTOTPEnrollmentStarted        EventName = "totp.enrollment_started"
	EventTOTPActivated                EventName = "totp.activated"
	EventTOTPDisabled                 EventName = "totp.disabled"
	EventTOTPVerified                 EventName = "totp.verified"
	EventTOTPReplayRejected           EventName = "totp.replay_rejected"
	EventRecoveryCodeConsumed         EventName = "recovery_code.consumed"
	EventRecoveryCodesRegenerated     EventName = "recovery_codes.regenerated"
	EventPasskeyRegistered            EventName = "passkey.registered"
	EventPasskeyDeleted               EventName = "passkey.deleted"
	EventPasskeyAuthenticated         EventName = "passkey.authenticated"
	EventUserCredentialsRevoked       EventName = "user.credentials_revoked"
	EventSecondFactorReset            EventName = "user.second_factor_reset"
	EventUserAnonymized               EventName = "user.anonymized"
	EventUserLocked                   EventName = "user.locked"
	EventUserProfileUpdated           EventName = "user.profile_updated"
	EventSessionCreated               EventName = "session.created"
	EventSessionRevoked               EventName = "session.revoked"
	EventUserSessionsRevoked          EventName = "session.user_revoked"
	EventPATCreated                   EventName = "pat.created"
	EventPATRevoked                   EventName = "pat.revoked"
	EventPATAuthenticated             EventName = "pat.authenticated"
	EventPATRejected                  EventName = "pat.rejected"
	EventSSOChallengeIssued           EventName = "sso.challenge_issued"
	EventSSOLinked                    EventName = "sso.linked"
	EventSSOUnlinked                  EventName = "sso.unlinked"
	EventSSOAuthenticated             EventName = "sso.authenticated"
	EventSSOJITProvisioned            EventName = "sso.jit_provisioned"
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
	EventOAuthClientSecretRotated     EventName = "oauth.client.secret_rotated"
	EventOAuthClientJWKSReplaced      EventName = "oauth.client.jwks_replaced"
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
	EventOAuthCodeReuseDetected       EventName = "oauth.authorization_code.reuse_detected"
	EventOAuthConsentRevoked          EventName = "oauth.consent.revoked"
)

// EventMeta is embedded by every hook payload and event. ID is a UUIDv7
// suitable as an idempotency key or outbox messageId; AuditID references the
// audit event committed with the change (empty for advisory events that have
// no audit of their own).
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

// UserCreateChange carries a created account with its primary email and
// initial membership.
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

// UserStatusChange covers both directions of the user lifecycle; Disabled
// tells them apart, as does the EventMeta name.
type UserStatusChange struct {
	EventMeta
	UserID   string
	Disabled bool
}

// UserProfileChange carries a profile display-name update and the value it
// replaced.
type UserProfileChange struct {
	EventMeta
	User            User
	PreviousProfile string
}

// WorkspaceChange carries a workspace update, disable or enable together
// with the state it replaced.
type WorkspaceChange struct {
	EventMeta
	Workspace Workspace
	Previous  Workspace
}

// MembershipChange covers membership addition, status change and removal.
// Previous is nil for an addition, and Removed marks a removal whose
// Membership field holds the final state.
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

// WorkspaceDomainChange covers workspace-domain creation, confirmation,
// policy update and removal; the EventMeta name tells them apart and Removed
// marks a removal whose Domain field holds the final state. The Challenge is
// deliberately included: it is published in public DNS and is not a secret.
type WorkspaceDomainChange struct {
	EventMeta
	Domain  WorkspaceDomain
	Removed bool
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

// SecondFactorReset reports the administrative removal of every second
// factor of a user: the TOTP factor with its recovery codes and all
// passkeys, with the user's sessions revoked in the same transaction.
type SecondFactorReset struct {
	EventMeta
	UserID string
}

// UserAnonymization is the transactional-hook change for AnonymizeUser: the
// user's mutable personal data is scrubbed and their credentials revoked in
// the same transaction, while the append-only audit chain is preserved.
type UserAnonymization struct {
	EventMeta
	UserID string
}

// RecoveryCodeRegeneration reports the replacement of a user's recovery
// codes; payloads carry only the count, never code material.
type RecoveryCodeRegeneration struct {
	EventMeta
	UserID            string
	RecoveryCodeCount int
}

// SessionCreation carries the created session record; its Digest is always
// nil so hook payloads never see token material.
type SessionCreation struct {
	EventMeta
	Session Session
	// Request is the client network context observed at creation.
	Request RequestMetadata
}

type SessionRevocation struct {
	EventMeta
	SessionID string
	UserID    string
}

// UserSessionRevocation reports a bulk "log out everywhere" for one user.
type UserSessionRevocation struct {
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

// ClientAuditRecord carries a host-supplied audit entry recorded through
// RecordAudit, with the derived actor and timestamp already enforced.
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

// OAuthChange is the shared payload of every OAuth hook call and event.
// Only the identifiers that apply to the specific change are set; raw codes,
// tokens and secrets never appear.
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

// Listener event payloads mirror the committed fact they announce: the
// embedded EventMeta identifies the event, the remaining fields are a
// scrubbed snapshot of the affected records. Like transaction payloads, they
// never carry passwords, hashes, raw tokens, secrets, or digests; fields that
// are not otherwise documented are exactly the persisted values.
type BootstrapCompletedEvent struct {
	EventMeta
	User      User
	Workspace Workspace
}

// SignUpCompletedEvent reports a successful self-service registration: the
// created account and the workspace it administers. Collisions with an
// existing address emit no event so listeners cannot become an enumeration
// side channel.
type SignUpCompletedEvent struct {
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

// PasswordRehashedEvent reports the transparent hash renewal performed after
// a successful authentication when the hashing parameters changed.
type PasswordRehashedEvent struct {
	EventMeta
	UserID string
}

// AuthenticationEvent reports every successful authentication, whatever the
// method.
type AuthenticationEvent struct {
	EventMeta
	Authentication Authentication
	// Request carries the client network context supplied by the host through
	// WithRequestMetadata, so listeners can throttle or alert by address
	// without re-reading the audit log.
	Request RequestMetadata
}

// AuthenticationFailureEvent reports a failed authentication attempt. UserID
// is empty when the failure cannot be attributed to an existing account.
type AuthenticationFailureEvent struct {
	EventMeta
	Method AuthMethod
	UserID string
	Reason string
	// Request carries the client network context supplied by the host through
	// WithRequestMetadata, so listeners can throttle or alert by address
	// without re-reading the audit log.
	Request RequestMetadata
}

// StepUpDeniedEvent is an advisory signal that an operation was refused for
// lack of a fresh AAL2 authentication; it carries no audit of its own.
type StepUpDeniedEvent struct {
	EventMeta
	UserID string
}

// AuthorizationDeniedEvent is an advisory signal that a workspace
// authorization failed; it carries no audit of its own. RequiredRole is
// empty for permission-based checks.
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

type EmailVerificationResentEvent struct {
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

// UserAnonymizedEvent reports that an instance administrator pseudonymized a
// user: their mutable personal data (display name, email addresses, SSO and
// credential names) was scrubbed and their credentials revoked, while the
// append-only audit chain was preserved. It is the library's answer to a
// right-to-erasure request; hosts erase their own application-owned data
// separately.
type UserAnonymizedEvent struct {
	EventMeta
	UserID string
}

// SecondFactorResetEvent reports that an instance administrator removed
// every second factor of the user (TOTP, recovery codes, passkeys) and
// revoked their sessions — the total-loss recovery path. Hosts should
// notify the affected user out of band.
type SecondFactorResetEvent struct {
	EventMeta
	UserID string
}

// RecoveryCodesRegeneratedEvent reports that the user replaced their
// recovery codes; the previous set stopped working in the same transaction.
type RecoveryCodesRegeneratedEvent struct {
	EventMeta
	UserID            string
	RecoveryCodeCount int
}

// SessionCreatedEvent reports a new server-side session. The Session carries
// a nil Digest and the raw token is never part of any event.
// AuthenticateSession emits no per-validation event — it runs on every
// request and would flood listeners; only the audit log records validations.
type SessionCreatedEvent struct {
	EventMeta
	Session Session
	// Request carries the client network context supplied by the host through
	// WithRequestMetadata, so listeners can alert on new devices without
	// re-reading the audit log.
	Request RequestMetadata
}

type SessionRevokedEvent struct {
	EventMeta
	SessionID string
	UserID    string
}

// UserSessionsRevokedEvent reports that every active session of the user was
// revoked in one operation ("log out everywhere").
type UserSessionsRevokedEvent struct {
	EventMeta
	UserID string
}

// UserLockedEvent is emitted once when consecutive failures reach the
// lockout threshold, so listeners can alert without counting failures
// themselves.
type UserLockedEvent struct {
	EventMeta
	UserID      string
	LockedUntil time.Time
	// Request carries the client network context supplied by the host through
	// WithRequestMetadata, so listeners can throttle or alert by address
	// without re-reading the audit log.
	Request RequestMetadata
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

// PATRejectedEvent reports a rejected PAT authentication. The token owner,
// when identifiable, is only in the associated audit — malformed tokens have
// no attributable user.
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

// SSOJITProvisionedEvent reports a just-in-time provisioned account: the
// passwordless user created inside FinishSSO from a verified IdP email under
// a confirmed auto-join domain, its verified primary email, the configured
// membership and the linked identity. It is emitted alongside user.created,
// sso.linked and authentication.succeeded for the same commit.
type SSOJITProvisionedEvent struct {
	EventMeta
	User       User
	Email      EmailAddress
	Membership Membership
	Identity   SSOIdentity
	// DomainID references the confirmed workspace domain whose auto-join
	// policy produced the account.
	DomainID string
}

// WorkspaceDomainEvent is the shared payload of the workspace-domain
// lifecycle events (created, confirmed, policy updated, removed); the
// EventMeta name tells them apart. The Challenge is deliberately included:
// it is published in public DNS and is not a secret.
type WorkspaceDomainEvent struct {
	EventMeta
	Domain WorkspaceDomain
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

// SCIMUserEvent is the shared payload of every SCIM user lifecycle event
// (provisioned, updated, activated, suspended, deprovisioned); the EventMeta
// name tells them apart.
type SCIMUserEvent struct {
	EventMeta
	User SCIMUser
}

// SCIMGroupEvent is the shared payload of every SCIM group lifecycle event
// (created, updated, deleted, members changed); the EventMeta name tells
// them apart.
type SCIMGroupEvent struct {
	EventMeta
	Group SCIMGroup
}

// OAuthEvent is the shared payload of every OAuth event, distinguished by
// the EventMeta name of its OAuthChange.
type OAuthEvent struct {
	OAuthChange
}

// UserStatusEvent reports a user being disabled or re-enabled; Disabled
// tells the directions apart.
type UserStatusEvent struct {
	EventMeta
	UserID   string
	Disabled bool
}

// UserProfileUpdatedEvent reports a profile display-name update.
type UserProfileUpdatedEvent struct {
	EventMeta
	UserID          string
	DisplayName     string
	PreviousProfile string
}

// WorkspaceChangedEvent reports a workspace update, disable or enable
// together with the state it replaced.
type WorkspaceChangedEvent struct {
	EventMeta
	Workspace Workspace
	Previous  Workspace
}

// MembershipChangedEvent reports a membership addition, status change or
// removal. Previous is nil for an addition and Removed marks a removal.
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

// TransactionHook lets the host add its own writes to a Credbound mutation.
// Hooks run sequentially inside the store transaction, after the mutation
// and before the audit write, so returning an error aborts the whole commit;
// errors that are not sentinel errors surface as ErrTransactionRejected.
// Hooks must not perform external I/O, invoke another Manager mutation,
// retain the Tx, or use it from another goroutine. Implementations embed
// UnimplementedTransactionHook to stay compatible as methods are added.
type TransactionHook interface {
	unimplementedTransactionHook()

	ApplyUserCreate(context.Context, Tx, UserCreateChange) error
	ApplyWorkspaceCreate(context.Context, Tx, WorkspaceCreateChange) error
	ApplyUserStatusChange(context.Context, Tx, UserStatusChange) error
	ApplyUserProfileChange(context.Context, Tx, UserProfileChange) error
	ApplyWorkspaceChange(context.Context, Tx, WorkspaceChange) error
	ApplyMembershipChange(context.Context, Tx, MembershipChange) error
	ApplyWorkspaceInvitationChange(context.Context, Tx, WorkspaceInvitationChange) error
	ApplyWorkspaceDomainChange(context.Context, Tx, WorkspaceDomainChange) error
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
	ApplySecondFactorReset(context.Context, Tx, SecondFactorReset) error
	ApplyUserAnonymization(context.Context, Tx, UserAnonymization) error
	ApplyRecoveryCodeRegeneration(context.Context, Tx, RecoveryCodeRegeneration) error
	ApplySessionCreation(context.Context, Tx, SessionCreation) error
	ApplySessionRevocation(context.Context, Tx, SessionRevocation) error
	ApplyUserSessionRevocation(context.Context, Tx, UserSessionRevocation) error
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

// EventListener observes committed facts. Listeners run synchronously after
// the commit; their errors and panics are recorded through the Observer for
// observability only and never propagate or interrupt other listeners.
// Delivery is best effort — guaranteed delivery belongs in a host-owned
// outbox written from a TransactionHook, with EventMeta.ID as the
// idempotency key. Implementations embed UnimplementedEventListener to stay
// compatible as methods are added. Events never carry secrets.
type EventListener interface {
	unimplementedEventListener()

	OnBootstrapCompleted(context.Context, BootstrapCompletedEvent) error
	OnSignUpCompleted(context.Context, SignUpCompletedEvent) error
	OnUserCreated(context.Context, UserCreatedEvent) error
	OnWorkspaceCreated(context.Context, WorkspaceCreatedEvent) error
	OnUserStatusChanged(context.Context, UserStatusEvent) error
	OnUserProfileUpdated(context.Context, UserProfileUpdatedEvent) error
	OnWorkspaceChanged(context.Context, WorkspaceChangedEvent) error
	OnMembershipChanged(context.Context, MembershipChangedEvent) error
	OnWorkspaceInvitationCreated(context.Context, WorkspaceInvitationEvent) error
	OnWorkspaceInvitationAccepted(context.Context, WorkspaceInvitationEvent) error
	OnWorkspaceInvitationRevoked(context.Context, WorkspaceInvitationEvent) error
	OnWorkspaceDomainCreated(context.Context, WorkspaceDomainEvent) error
	OnWorkspaceDomainConfirmed(context.Context, WorkspaceDomainEvent) error
	OnWorkspaceDomainPolicyUpdated(context.Context, WorkspaceDomainEvent) error
	OnWorkspaceDomainRemoved(context.Context, WorkspaceDomainEvent) error
	OnPasswordChanged(context.Context, PasswordChangedEvent) error
	OnPasswordRehashed(context.Context, PasswordRehashedEvent) error
	OnAuthenticationSucceeded(context.Context, AuthenticationEvent) error
	OnAuthenticationFailed(context.Context, AuthenticationFailureEvent) error
	OnStepUpDenied(context.Context, StepUpDeniedEvent) error
	OnAuthorizationDenied(context.Context, AuthorizationDeniedEvent) error
	OnEmailAdded(context.Context, EmailAddedEvent) error
	OnEmailConfirmed(context.Context, EmailConfirmedEvent) error
	OnEmailVerificationResent(context.Context, EmailVerificationResentEvent) error
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
	OnSecondFactorReset(context.Context, SecondFactorResetEvent) error
	OnUserAnonymized(context.Context, UserAnonymizedEvent) error
	OnRecoveryCodesRegenerated(context.Context, RecoveryCodesRegeneratedEvent) error
	OnSessionCreated(context.Context, SessionCreatedEvent) error
	OnSessionRevoked(context.Context, SessionRevokedEvent) error
	OnUserSessionsRevoked(context.Context, UserSessionsRevokedEvent) error
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
	OnSSOJITProvisioned(context.Context, SSOJITProvisionedEvent) error
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

// AnyEventListener is an optional extension an EventListener may also
// implement to receive every event through a single method — the natural
// shape for an analytics feed, a host-owned outbox relay, or a webhook
// dispatcher that would otherwise implement every typed method. For each
// emitted event the registry first invokes the typed method, then OnAnyEvent
// on the same listener, under the same post-commit, best-effort delivery:
// errors and panics are observed and never propagate. The event value is the
// same typed struct the typed method received (a PasskeyRegisteredEvent, an
// OAuthEvent, …), so a dispatcher can type-switch on it or marshal it
// directly, and every one embeds EventMeta for the idempotency key.
type AnyEventListener interface {
	OnAnyEvent(ctx context.Context, name EventName, event any) error
}

// Subscription undoes an AddTransactionHook or AddEventListener
// registration. Remove is idempotent.
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

// AddTransactionHook registers a hook after construction, in addition to
// Config.TransactionHooks. It returns the Subscription that removes it; a
// nil hook is ignored and yields a no-op Subscription.
func (m *Manager) AddTransactionHook(hook TransactionHook) Subscription {
	if nilInterface(hook) {
		return &eventSubscription{remove: func() {}}
	}
	return m.events.addTransactionHook(hook)
}

// AddEventListener registers a listener after construction, in addition to
// Config.EventListeners. It returns the Subscription that removes it; a nil
// listener is ignored and yields a no-op Subscription.
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
	listeners := r.eventListeners()
	if len(listeners) == 0 {
		return
	}
	// The callback carries the typed event value; replaying it against the
	// generated recorder recovers that value once, so AnyEventListener
	// catch-alls receive the same struct the typed methods do.
	var recorder anyEventRecorder
	_ = call(&recorder)
	for _, registered := range listeners {
		started := r.now()
		err, panicked := safeEventCall(func() error { return call(registered.listener) })
		r.observer.Observe(ctx, Operation{Name: "event." + string(name), Outcome: callbackOutcome(err, panicked), Duration: r.now().Sub(started)})
		catchAll, ok := registered.listener.(AnyEventListener)
		if !ok {
			continue
		}
		started = r.now()
		err, panicked = safeEventCall(func() error { return catchAll.OnAnyEvent(ctx, name, recorder.event) })
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
	event := AuthenticationEvent{EventMeta: meta, Authentication: cloneAuthentication(authentication), Request: requestMetadataFromContext(ctx)}
	m.events.emit(ctx, EventAuthenticationSucceeded, func(listener EventListener) error {
		return listener.OnAuthenticationSucceeded(ctx, event)
	})
}

func (m *Manager) emitAuthenticationFailed(ctx context.Context, operation string, audit AuditEvent, method AuthMethod, userID, reason string) {
	meta, err := m.newEventMeta(EventAuthenticationFailed, operation, userID, "", audit)
	if err != nil {
		return
	}
	event := AuthenticationFailureEvent{EventMeta: meta, Method: method, UserID: userID, Reason: reason, Request: requestMetadataFromContext(ctx)}
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
