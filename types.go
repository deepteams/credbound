package credbound

import (
	"encoding/json"
	"iter"
	"time"
)

// Role names a workspace role. The built-in member and admin roles always
// exist; Config.WorkspaceRoles may register additional roles that implicitly
// inherit from member. An unknown role fails closed everywhere.
type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

// WorkspacePermission names a tenant-scoped capability checked by
// AuthorizePermission. The admin role always holds every registered
// workspace permission, including host-defined ones.
type WorkspacePermission string

const (
	PermissionWorkspaceAccess        WorkspacePermission = "workspace.access"
	PermissionWorkspaceUsersRead     WorkspacePermission = "workspace.users.read"
	PermissionWorkspaceUsersWrite    WorkspacePermission = "workspace.users.write"
	PermissionWorkspaceSettingsWrite WorkspacePermission = "workspace.settings.write"
	PermissionWorkspaceRBACWrite     WorkspacePermission = "workspace.rbac.write"
	PermissionWorkspaceAuditRead     WorkspacePermission = "workspace.audit.read"
	PermissionOAuthResourceManage    WorkspacePermission = "oauth.resource.manage"
)

// RoleDefinition registers a workspace role in the immutable RBAC catalog
// validated by New. A definition named member or admin adds permissions to
// the built-in role without removing its guarantees; any other role
// implicitly inherits from member. Inheritance must be acyclic.
type RoleDefinition struct {
	Role        Role
	Permissions []WorkspacePermission
	// Inherits lists roles whose permissions this role also receives.
	Inherits []Role
}

// MembershipStatus is the lifecycle state of a workspace membership. A
// suspended membership fails every authorization but retains its role.
type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "active"
	MembershipSuspended MembershipStatus = "suspended"
)

// ProvisioningSourceLocal marks a membership managed by local operations. A
// SCIM-managed membership instead carries the UUIDv7 of its configuration,
// and ordinary local mutations cannot overwrite it.
const ProvisioningSourceLocal = "local"

// InstanceRole is an instance-administration role, independent of workspace
// RBAC. The set is closed: only the five constants below exist, and only
// root may grant or remove instance roles.
type InstanceRole string

const (
	InstanceRoleRoot      InstanceRole = "root"
	InstanceRoleDeveloper InstanceRole = "developer"
	InstanceRoleSupport   InstanceRole = "support"
	InstanceRoleMarketing InstanceRole = "marketing"
	InstanceRoleSales     InstanceRole = "sales"
)

// Permission names an instance-administration capability checked by
// AuthorizeAdmin. Each InstanceRole maps to an explicit permission set;
// services authorize by permission, never by comparing role names.
type Permission string

const (
	PermissionAdminAccess        Permission = "admin.access"
	PermissionAuditRead          Permission = "admin.audit.read"
	PermissionSettingsRead       Permission = "admin.settings.read"
	PermissionSettingsWrite      Permission = "admin.settings.write"
	PermissionUsersRead          Permission = "admin.users.read"
	PermissionUsersWrite         Permission = "admin.users.write"
	PermissionWorkspacesRead     Permission = "admin.workspaces.read"
	PermissionWorkspacesWrite    Permission = "admin.workspaces.write"
	PermissionRBACRead           Permission = "admin.rbac.read"
	PermissionRBACWrite          Permission = "admin.rbac.write"
	PermissionInstanceRolesRead  Permission = "admin.instance_roles.read"
	PermissionInstanceRolesWrite Permission = "admin.instance_roles.write"
)

// InstanceAdministrator records the instance role held by a user. The first
// account created by Bootstrap atomically receives root.
type InstanceAdministrator struct {
	UserID    string
	Role      InstanceRole
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TrustedRequest is constructed by a trusted server adapter, never from
// client-controlled URL, Host, Origin or forwarding headers.
// TrustedRequestFromAddr derives it correctly from the observed network
// peer.
type TrustedRequest struct {
	// Local reports that the transport peer is a loopback address. When set,
	// RequireAdminMutation waives the AAL2 step-up for administrative
	// mutations, so it must never be copied from a request parameter,
	// header or body.
	Local bool
}

// AuthMethod identifies how an Authentication was produced.
type AuthMethod string

const (
	MethodPassword AuthMethod = "password"
	MethodTOTP     AuthMethod = "totp"
	MethodPasskey  AuthMethod = "passkey"
	MethodPAT      AuthMethod = "pat"
	MethodSSO      AuthMethod = "sso"
	MethodEmail    AuthMethod = "email"
)

// AssuranceLevel is the authenticator assurance level of an Authentication,
// after NIST 800-63B: AAL1 for a single factor, AAL2 once a second factor
// (TOTP, recovery code) or a strong single ceremony (passkey, SSO) has been
// verified.
type AssuranceLevel uint8

const (
	AAL1 AssuranceLevel = 1
	AAL2 AssuranceLevel = 2
)

// User is a global account. Email mirrors the primary EmailAddress;
// LastSeenAt reflects the latest successful authentication across all
// factors and is updated atomically with the authentication audit.
type User struct {
	ID          string
	Email       string
	DisplayName string
	Disabled    bool
	LastSeenAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// EmailAddress is one of a user's globally unique, normalized addresses.
// Exactly one address per user is primary; an address becomes usable for
// sign-in only once VerifiedAt is set.
type EmailAddress struct {
	ID         string
	UserID     string
	Address    string
	Primary    bool
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// EmailVerificationCredential is the persisted proof for a pending email
// addition. Only the HMAC digest of the token is stored.
type EmailVerificationCredential struct {
	EmailID   string
	Digest    []byte
	ExpiresAt time.Time
}

// IssuedEmailVerification carries the raw verification token exactly once,
// from BeginEmailAddition. The host delivers it to the new address and never
// stores it.
type IssuedEmailVerification struct {
	Email EmailAddress
	Token string
}

// PasswordResetCredential is the persisted single-use reset proof. Only the
// HMAC digest of the token is stored.
type PasswordResetCredential struct {
	ID        string
	UserID    string
	Digest    []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// IssuedPasswordReset carries the single-use reset token exactly once. The
// host service delivers it to the address that requested the reset and never
// stores it.
type IssuedPasswordReset struct {
	UserID    string
	Token     string
	ExpiresAt time.Time
}

// EmailAuthenticationCredential is the persisted single-use proof behind a
// magic link or email OTP. Only the HMAC digest of the token or code is
// stored.
type EmailAuthenticationCredential struct {
	ID        string
	UserID    string
	EmailID   string
	Digest    []byte
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// IssuedEmailAuthentication carries the single-use magic-link token exactly
// once. The host service delivers it to the verified address and never
// stores it.
type IssuedEmailAuthentication struct {
	UserID    string
	EmailID   string
	Token     string
	ExpiresAt time.Time
}

// IssuedEmailOTP carries the single-use numeric code exactly once, with the
// sealed continuation the host must hand back to CompleteEmailOTP. Code is
// empty when the address was not eligible; the host then sends no email but
// answers the end user identically.
type IssuedEmailOTP struct {
	UserID       string
	EmailID      string
	Code         string
	Continuation string
	ExpiresAt    time.Time
}

// Workspace is a tenant. A workspace with DisabledAt set denies every
// tenant-scoped capability until it is re-enabled.
type Workspace struct {
	ID   string
	Name string
	// RequireMFA rejects interactive access below AAL2 for every member of
	// the workspace. Non-interactive credentials such as PATs, whose
	// creation already required a step-up, are not affected.
	RequireMFA bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

// Membership binds a user to a workspace with a role and lifecycle status.
type Membership struct {
	WorkspaceID string
	UserID      string
	Role        Role
	Status      MembershipStatus
	// ProvisioningSource identifies who owns the membership: the literal
	// "local", or the UUIDv7 of the SCIM configuration that manages it.
	// SCIM-managed memberships reject ordinary local mutations.
	ProvisioningSource string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// PasswordCredential is the persisted password hash of a user. Hash is an
// encoded derivation (Argon2id by default) and never the password itself.
type PasswordCredential struct {
	UserID    string
	Hash      string
	UpdatedAt time.Time
}

// TOTPFactor is a user's persisted TOTP enrollment. The secret is sealed
// with the Manager's AEAD key, and LastUsedStep prevents replay of an
// already accepted time step.
type TOTPFactor struct {
	UserID          string
	EncryptedSecret []byte
	// Active becomes true only after ConfirmTOTPEnrollment proved a valid
	// code; an inactive enrollment never gates authentication.
	Active       bool
	LastUsedStep int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RecoveryCode is one single-use TOTP fallback code, persisted as a peppered
// HMAC digest only.
type RecoveryCode struct {
	UserID string
	Digest []byte
	UsedAt *time.Time
}

// Passkey is a registered WebAuthn credential. CredentialJSON holds the
// provider's sealed credential state and is scrubbed from every value the
// Manager returns to callers.
type Passkey struct {
	ID             string
	UserID         string
	Name           string
	CredentialID   []byte
	CredentialJSON []byte
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

// WorkspaceInvitation invites an email address into a workspace with a
// pre-assigned role. The digest is stored server-side only; the single-use
// token is returned once at creation for the host to deliver.
type WorkspaceInvitation struct {
	ID             string
	WorkspaceID    string
	Email          string
	Role           Role
	InvitedBy      string
	Digest         []byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
	AcceptedAt     *time.Time
	AcceptedUserID string
	RevokedAt      *time.Time
}

// IssuedWorkspaceInvitation carries the raw invitation token exactly once,
// from InviteToWorkspace. The host delivers it to the invited address and
// never stores it.
type IssuedWorkspaceInvitation struct {
	Invitation WorkspaceInvitation
	Token      string
}

// InviteToWorkspaceInput describes a workspace invitation: the address to
// invite and the role the invitee will receive on acceptance.
type InviteToWorkspaceInput struct {
	Email string
	Role  Role
}

// WorkspaceDomain is a workspace-owned email domain. It is created pending
// with a DNS challenge value; the host proves control of the domain (by
// convention a TXT record carrying Challenge) out of band and confirms it
// with ConfirmWorkspaceDomain. Only a confirmed domain carries policy:
// auto-join (JIT provisioning through the trusted SSO provider
// configuration) and SSO enforcement. A domain name is globally unique
// across workspaces.
type WorkspaceDomain struct {
	ID          string
	WorkspaceID string
	// Domain is the normalized, lowercase registrable DNS name
	// ("corp.example.com").
	Domain string
	// Challenge is the DNS TXT value proving control of the domain. It is
	// deliberately not a secret credential — the host publishes it in public
	// DNS — so it is stored in plaintext and remains visible on the record so
	// the host can re-display it until the domain is confirmed.
	Challenge string
	// ConfirmedAt is set once the host asserted that DNS verification
	// completed. An unconfirmed domain carries no policy effect.
	ConfirmedAt *time.Time
	// AutoJoin enables JIT provisioning: an unknown SSO identity whose
	// verified email is under this domain and arrives through the trusted
	// provider configuration is provisioned as a passwordless member.
	AutoJoin bool
	// AutoJoinRole is the workspace role granted to JIT-provisioned users.
	AutoJoinRole Role
	// SSOProviderConfigurationID names the registered SSO provider
	// configuration this domain trusts for JIT provisioning.
	SSOProviderConfigurationID string
	// EnforceSSO rejects password, magic-link and email-OTP authentication
	// for addresses under the domain with ErrSSORequired.
	EnforceSSO bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// IssuedWorkspaceDomain is the result of CreateWorkspaceDomain: the pending
// record and its DNS challenge value. Unlike single-use tokens the challenge
// is not secret (it is published in DNS) and also stays on the record.
type IssuedWorkspaceDomain struct {
	Domain    WorkspaceDomain
	Challenge string
}

// WorkspaceDomainPolicyInput replaces the policy of a confirmed workspace
// domain: the auto-join flag with its target role, the SSO provider
// configuration the domain trusts, and the SSO enforcement flag. A zero
// AutoJoinRole means member. When AutoJoin or EnforceSSO is set the provider
// configuration must be registered with the Manager.
type WorkspaceDomainPolicyInput struct {
	AutoJoin                   bool
	AutoJoinRole               Role
	SSOProviderConfigurationID string
	EnforceSSO                 bool
}

// RegisterFromInvitationInput carries the profile the invitee chooses when
// registering a new account from an invitation token. The invited address
// becomes the verified primary email.
type RegisterFromInvitationInput struct {
	DisplayName string
	Password    string
}

// LoginThrottle tracks consecutive authentication failures for one user. It
// backs the built-in account lockout and is reset by any successful
// authentication.
type LoginThrottle struct {
	UserID         string
	FailedAttempts int64
	LockedUntil    *time.Time
	UpdatedAt      time.Time
}

// TOTPStatus is the read-only state of a user's TOTP factor. It never
// contains the secret, the otpauth URI or any recovery code material.
type TOTPStatus struct {
	Enrolled            bool
	Active              bool
	UnusedRecoveryCodes int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// PAT is the persisted metadata of a personal access token. The raw token
// has the form cbp_<prefix>_<secret>; Prefix enables an indexed lookup and
// only the HMAC Digest of the full token is stored. A PAT bound to a
// WorkspaceID authenticates only within that workspace.
type PAT struct {
	ID          string
	UserID      string
	Name        string
	Prefix      string
	Digest      []byte
	WorkspaceID string
	Scopes      []string
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

// IssuedPAT carries the raw PAT exactly once, from CreatePAT. The host shows
// it to the user once and never stores it.
type IssuedPAT struct {
	PAT   PAT
	Token string
}

// Authentication is the server-side capability returned by every successful
// authentication. The host stores it in its own session and passes it back
// as the actor of later operations; because every authorization decision
// trusts its fields, it must never be reconstructed from data a client
// supplies. Credbound issues no cookies or JWTs — the session strategy
// belongs to the host.
type Authentication struct {
	UserID string
	// Method records the factor that produced this context (password, totp,
	// passkey, sso, email, or pat). Non-interactive methods (PAT) are
	// rejected by step-up checks regardless of age.
	Method AuthMethod
	// Level is the assurance reached so far. AAL1 contexts are denied
	// sensitive operations until VerifyTOTP, a passkey or an SSO step-up
	// promotes the session to AAL2.
	Level AssuranceLevel
	// AuthenticatedAt is when the factor was verified. RequireStepUp accepts
	// only interactive AAL2 contexts whose AuthenticatedAt falls within
	// Config.StepUpMaxAge, so the host must preserve this timestamp rather
	// than refresh it.
	AuthenticatedAt time.Time
	// SecondFactorRequired reports that the account has an active TOTP
	// factor which has not been verified yet. The host should defer creating
	// the final session until VerifyTOTP upgrades the context.
	SecondFactorRequired bool
	// WorkspaceID restricts the context to one workspace. It is set for
	// workspace-bound PATs; authorization in any other workspace fails.
	WorkspaceID string
	// Scopes limits what the credential may do (PATs). Empty means the
	// context carries no scope restriction of its own.
	Scopes []string
}

// Interactive reports whether the context was produced by a user-present
// ceremony rather than a stored credential such as a PAT. Only interactive
// contexts can satisfy step-up requirements.
func (a Authentication) Interactive() bool {
	return a.Method == MethodPassword || a.Method == MethodTOTP || a.Method == MethodPasskey || a.Method == MethodSSO || a.Method == MethodEmail
}

// HasScope reports whether the context carries the required scope. An empty
// requirement always passes and the literal "*" scope matches everything.
// AuthorizePermission consults it for every scoped authentication, so hosts
// only need it for checks outside the workspace RBAC model.
func (a Authentication) HasScope(required string) bool {
	if required == "" {
		return true
	}
	for _, scope := range a.Scopes {
		if scope == required || scope == "*" {
			return true
		}
	}
	return false
}

// Session is a persisted server-side session: an immutable snapshot of the
// Authentication that created it, plus the device metadata observed at
// creation. The raw cbs_ token is returned exactly once by CreateSession and
// only its HMAC digest is stored. A session never upgrades its assurance
// level in place — after VerifyTOTP or any other AAL transition the host
// mints a new session and revokes the previous one, which doubles as
// fixation protection.
type Session struct {
	ID     string
	UserID string
	// Method and Level snapshot the creating Authentication verbatim; they
	// never change for the lifetime of the session.
	Method AuthMethod
	Level  AssuranceLevel
	// AuthenticatedAt is copied from the creating Authentication so step-up
	// freshness keeps measuring the factor verification, not session reuse.
	AuthenticatedAt      time.Time
	SecondFactorRequired bool
	// UserAgent and IPAddress are the sanitized RequestMetadata observed when
	// the session was created, for device listings.
	UserAgent string
	IPAddress string
	// Digest is the HMAC of the raw token under the derived key (domain
	// "session:"). It is scrubbed from listings and from every value the
	// Manager returns.
	Digest    []byte
	CreatedAt time.Time
	// LastSeenAt is telemetry only: expiry is absolute (CreatedAt plus
	// Config.SessionTTL) and is never extended by activity.
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// IssuedSession carries the raw session token exactly once, from
// CreateSession. The host transports it (typically in a cookie) and never
// stores it; only the digest is persisted.
type IssuedSession struct {
	Session Session
	Token   string
}

// CreateSessionInput reserves room for future per-session options. Device
// metadata is not part of it: CreateSession reads the sanitized
// RequestMetadata attached to the context with WithRequestMetadata.
type CreateSessionInput struct{}

// AuditOutcome records whether the audited action succeeded or failed.
type AuditOutcome string

const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditFailed    AuditOutcome = "failed"
)

// ActorKind classifies the audit actor: an authenticated user, a service
// credential (SCIM, OAuth client), or the system itself.
type ActorKind string

const (
	ActorUser    ActorKind = "user"
	ActorService ActorKind = "service"
	ActorSystem  ActorKind = "system"
)

// RequestMetadata carries the client network context of the request being
// served. The host service extracts it from its trusted proxy headers and
// attaches it with WithRequestMetadata; Credbound never reads transport
// headers itself. Both fields are sanitized and bounded before being audited.
type RequestMetadata struct {
	IPAddress string
	UserAgent string
}

// AuditEvent is one immutable entry of the append-only audit log. ID,
// ActorID and OccurredAt are always derived by Credbound so a consuming
// service cannot impersonate an actor or backdate an entry.
type AuditEvent struct {
	ID           string
	OccurredAt   time.Time
	ActorKind    ActorKind
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	WorkspaceID  string
	Outcome      AuditOutcome
	Reason       string
	IPAddress    string
	UserAgent    string
	// Sequence, PreviousHash and Hash are assigned by the store inside the
	// commit transaction and chain every event to its predecessor. A zero
	// Sequence marks an event recorded before the chain existed.
	Sequence     int64
	PreviousHash []byte
	Hash         []byte
}

// AuditChainReport summarizes a successful audit chain verification.
type AuditChainReport struct {
	Events       int64
	HeadSequence int64
	HeadHash     []byte
}

// SCIMGroupRoleMapping maps a directory group (by its external identifier)
// to a workspace role from the immutable catalog. When a user belongs to
// several mapped groups the highest Priority wins; two mappings of equal
// priority resolving to different roles fail closed with ErrConflict.
type SCIMGroupRoleMapping struct {
	ExternalID string
	Role       Role
	Priority   int
}

// SCIMConfiguration is the provisioning domain of one workspace: the default
// role for provisioned users, the group-to-role mappings, and whether
// directory-asserted primary emails are trusted as verified.
type SCIMConfiguration struct {
	ID          string
	WorkspaceID string
	Enabled     bool
	DefaultRole Role
	// TrustDirectoryEmails marks the primary address of provisioned users as
	// verified, making it usable for sign-in. Without it even the primary
	// SCIM address stays unverified.
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// SCIMCredential is the persisted metadata of a SCIM bearer credential. The
// raw token has the form cbs_<prefix>_<secret> and only its HMAC Digest is
// stored. A credential is a service identity and never represents a user.
type SCIMCredential struct {
	ID              string
	ConfigurationID string
	Prefix          string
	Digest          []byte
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	LastUsedAt      *time.Time
	RevokedAt       *time.Time
}

// IssuedSCIMCredential carries the raw SCIM bearer token exactly once, from
// CreateSCIMConfiguration or RotateSCIMCredential. The public Credential
// value has an empty Digest.
type IssuedSCIMCredential struct {
	Configuration SCIMConfiguration
	Credential    SCIMCredential
	Token         string
}

// SCIMAuthentication is the service capability obtained through
// AuthenticateSCIM. It scopes every provisioning operation to one
// configuration and its workspace and must never be constructed from fields
// freely supplied by a client.
type SCIMAuthentication struct {
	ConfigurationID string
	WorkspaceID     string
	CredentialID    string
	AuthenticatedAt time.Time
}

// SCIMEmail is one email attribute of a SCIM user profile. Only the primary
// address created with a new user joins the global identity model; the
// others remain tenant-scoped profile data.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMUser is the tenant-scoped link between a SCIM configuration and a
// global account. Its ID is the SCIM resource identifier and is distinct
// from UserID; unknown directory attributes are retained in Attributes.
// Deprovisioning sets DeprovisionedAt without disabling the global account.
type SCIMUser struct {
	ID              string
	ConfigurationID string
	UserID          string
	Schemas         []string
	ExternalID      string
	UserName        string
	DisplayName     string
	Emails          []SCIMEmail
	Attributes      map[string]json.RawMessage
	Active          bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeprovisionedAt *time.Time
}

// SCIMGroup is a persisted directory group. MemberIDs reference SCIMUser
// link identifiers, not global user IDs.
type SCIMGroup struct {
	ID              string
	ConfigurationID string
	ExternalID      string
	DisplayName     string
	MemberIDs       []string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	DeletedAt       *time.Time
}

// CreateSCIMConfigurationInput configures a new provisioning domain and its
// first credential. A zero DefaultRole means member; a nil
// CredentialExpiresAt issues a non-expiring credential.
type CreateSCIMConfigurationInput struct {
	DefaultRole          Role
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
	CredentialExpiresAt  *time.Time
}

// UpdateSCIMConfigurationInput replaces the role policy of a provisioning
// domain. Applying it recomputes the roles of every managed membership.
type UpdateSCIMConfigurationInput struct {
	DefaultRole          Role
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
}

// SCIMUserInput is the normalized SCIM user representation accepted by the
// provisioning operations. Active drives the membership status; false
// suspends the membership without touching the global account.
type SCIMUserInput struct {
	Schemas     []string
	ExternalID  string
	UserName    string
	DisplayName string
	Emails      []SCIMEmail
	Attributes  map[string]json.RawMessage
	Active      bool
}

// SCIMGroupInput is the SCIM group representation accepted by
// UpsertSCIMGroup. MemberIDs reference SCIMUser link identifiers.
type SCIMGroupInput struct {
	ExternalID  string
	DisplayName string
	MemberIDs   []string
}

// SCIMFilter is a single equality filter over a supported SCIM attribute.
// A zero value matches everything.
type SCIMFilter struct {
	Attribute string
	Value     string
}

// AuditInput is a host-supplied audit entry recorded through RecordAudit.
// Credbound derives the actor, identifier and timestamp itself.
type AuditInput struct {
	Action       string
	ResourceType string
	ResourceID   string
	WorkspaceID  string
	Outcome      AuditOutcome
	Reason       string
}

// SSOProviderKind is the protocol family of a registered SSO provider.
type SSOProviderKind string

const (
	SSOProviderGoogle    SSOProviderKind = "google"
	SSOProviderGitHub    SSOProviderKind = "github"
	SSOProviderMicrosoft SSOProviderKind = "microsoft"
	SSOProviderOIDC      SSOProviderKind = "oidc"
	SSOProviderSAML      SSOProviderKind = "saml"
)

// SSORequest carries Credbound's requirements to an SSOProvider when a
// ceremony begins. ForceReauthentication is set for step-up flows so the
// provider re-verifies the user and its own MFA instead of reusing an
// existing IdP session.
type SSORequest struct {
	ForceReauthentication bool
}

// SSOProviderChallenge is the provider's half of a started SSO ceremony: the
// URL to send the browser to and the opaque session state Credbound seals
// into the continuation.
type SSOProviderChallenge struct {
	RedirectURL string
	Session     []byte
}

// SSOClaims is the validated identity a provider returns from a finished
// ceremony. Issuer and Subject form the stable link key; Email is
// informational only and never triggers an automatic account match.
type SSOClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

// SSOChallenge is a started SSO ceremony: the provider redirect URL for the
// browser and the sealed continuation the host passes back to FinishSSO.
type SSOChallenge struct {
	RedirectURL  string
	Continuation string
}

// SSOIdentity is a persisted link between a user and an external identity.
// The (ProviderConfigurationID, Issuer, Subject) triplet is the stable key;
// Email is informational only.
type SSOIdentity struct {
	ID                      string
	UserID                  string
	ProviderConfigurationID string
	ProviderKind            SSOProviderKind
	Issuer                  string
	Subject                 string
	Email                   string
	CreatedAt               time.Time
	LastUsedAt              *time.Time
}

// PageRequest selects one page of a list. Cursor is an opaque value from a
// previous PageEnd (empty for the first page); Limit defaults to 50 and is
// capped at 100.
type PageRequest struct {
	Cursor string
	Limit  int
}

// PageEnd terminates a page: the opaque cursor of the next page and whether
// one exists.
type PageEnd struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

// PageEvent is one element of a paginated stream: either an item (Data set)
// or the final page_end (End set). Its JSON encoding is the NDJSON transport
// contract documented in the package overview.
type PageEvent[T any] struct {
	Type string   `json:"type"`
	Data *T       `json:"data,omitempty"`
	End  *PageEnd `json:"page_end,omitempty"`
}

// CollectPage drains a paginated sequence into its items and final PageEnd —
// the common case when a caller wants one page and a cursor rather than a
// stream:
//
//	pats, page, err := credbound.CollectPage(manager.PATs(ctx, authn, credbound.PageRequest{Limit: 50}))
//
// Streaming callers range over the sequence directly and forward each
// PageEvent (for example as NDJSON) instead.
func CollectPage[T any](seq iter.Seq2[PageEvent[T], error]) ([]T, PageEnd, error) {
	var items []T
	var end PageEnd
	for event, err := range seq {
		if err != nil {
			return nil, PageEnd{}, err
		}
		if event.Data != nil {
			items = append(items, *event.Data)
		}
		if event.End != nil {
			end = *event.End
		}
	}
	return items, end, nil
}

// ItemEvent wraps a value as the item element of a paginated stream. Store
// implementations use it to build PageEvent sequences.
func ItemEvent[T any](value T) PageEvent[T] {
	return PageEvent[T]{Type: "item", Data: &value}
}

// EndEvent wraps a PageEnd as the terminal element of a paginated stream.
func EndEvent[T any](end PageEnd) PageEvent[T] {
	return PageEvent[T]{Type: "page_end", End: &end}
}

// BootstrapInput describes the first account and workspace of an empty
// instance.
type BootstrapInput struct {
	Email         string
	DisplayName   string
	Password      string
	WorkspaceName string
}

// SignUpInput describes a self-service registration: the visitor's address,
// profile, chosen password and the name of the workspace created for them.
type SignUpInput struct {
	Email         string
	DisplayName   string
	Password      string
	WorkspaceName string
}

// SignUpResult is the outcome of a SignUp call. When ExistingAccount is true
// the address already belonged to an account: every other field is zero, the
// collision was reported only to the audit log, and the host must answer the
// end user exactly as if the registration had succeeded. Otherwise User and
// Workspace carry the created records; EmailVerification carries the
// single-use token proving the primary address (delivered by the host, never
// stored) unless Config.SignUp.AutoVerifyEmail is set, in which case
// Authentication instead carries an AAL1 password authentication.
type SignUpResult struct {
	User              User
	Workspace         Workspace
	Authentication    Authentication
	EmailVerification IssuedEmailVerification
	ExistingAccount   bool
}

// CreateUserInput describes an administratively created account. The address
// becomes the verified primary email and Role is the membership role in the
// target workspace.
type CreateUserInput struct {
	Email       string
	DisplayName string
	Password    string
	Role        Role
}

// CreateWorkspaceInput describes a new workspace. RequireMFA enables the
// workspace MFA policy from the start.
type CreateWorkspaceInput struct {
	Name       string
	RequireMFA bool
}

// UpdateWorkspaceInput carries a workspace update. Name is always applied.
type UpdateWorkspaceInput struct {
	Name string
	// RequireMFA toggles the workspace MFA policy; nil leaves it unchanged.
	RequireMFA *bool
}

// UpdateUserInput describes a user profile update. Emails are managed by the
// dedicated add/primary/remove operations and the disabled flag by the
// administrative lifecycle, so the only mutable profile field is the display
// name.
type UpdateUserInput struct {
	// DisplayName is the new 1-200 character profile name, trimmed.
	DisplayName string
}

// TOTPEnrollment is a started TOTP enrollment. URI is the otpauth:// URI the
// host renders as a QR code; it contains the secret and must not be
// persisted or logged.
type TOTPEnrollment struct {
	URI string
}

// CreatePATInput describes a new personal access token. An empty WorkspaceID
// leaves the token unbound; at least one scope is required and a nil
// ExpiresAt issues a non-expiring token.
type CreatePATInput struct {
	Name        string
	WorkspaceID string
	Scopes      []string
	ExpiresAt   *time.Time
}

// PasskeyChallenge is a started WebAuthn ceremony: the provider options the
// host forwards to the browser and the sealed continuation it passes back to
// the matching Finish call.
type PasskeyChallenge struct {
	Options      json.RawMessage `json:"options"`
	Continuation string          `json:"continuation"`
}

// PasskeyUser is the view of a user handed to a PasskeyProvider: the account
// and a lazy sequence of its registered credentials with the credential
// state decrypted.
type PasskeyUser struct {
	User        User
	Credentials func(yield func(Passkey, error) bool)
}
