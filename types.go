package credbound

import (
	"encoding/json"
	"time"
)

type Role string

const (
	RoleMember Role = "member"
	RoleAdmin  Role = "admin"
)

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

type RoleDefinition struct {
	Role        Role
	Permissions []WorkspacePermission
	Inherits    []Role
}

type MembershipStatus string

const (
	MembershipActive    MembershipStatus = "active"
	MembershipSuspended MembershipStatus = "suspended"
)

const ProvisioningSourceLocal = "local"

type InstanceRole string

const (
	InstanceRoleRoot      InstanceRole = "root"
	InstanceRoleDeveloper InstanceRole = "developer"
	InstanceRoleSupport   InstanceRole = "support"
	InstanceRoleMarketing InstanceRole = "marketing"
	InstanceRoleSales     InstanceRole = "sales"
)

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

type InstanceAdministrator struct {
	UserID    string
	Role      InstanceRole
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TrustedRequest is constructed by a trusted server adapter, never from
// client-controlled URL, Host, Origin or forwarding headers.
type TrustedRequest struct {
	Local bool
}

type AuthMethod string

const (
	MethodPassword AuthMethod = "password"
	MethodTOTP     AuthMethod = "totp"
	MethodPasskey  AuthMethod = "passkey"
	MethodPAT      AuthMethod = "pat"
	MethodSSO      AuthMethod = "sso"
)

type AssuranceLevel uint8

const (
	AAL1 AssuranceLevel = 1
	AAL2 AssuranceLevel = 2
)

type User struct {
	ID          string
	Email       string
	DisplayName string
	Disabled    bool
	LastSeenAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type EmailAddress struct {
	ID         string
	UserID     string
	Address    string
	Primary    bool
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type EmailVerificationCredential struct {
	EmailID   string
	Digest    []byte
	ExpiresAt time.Time
}

type IssuedEmailVerification struct {
	Email EmailAddress
	Token string
}

type Workspace struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

type Membership struct {
	WorkspaceID        string
	UserID             string
	Role               Role
	Status             MembershipStatus
	ProvisioningSource string
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type PasswordCredential struct {
	UserID    string
	Hash      string
	UpdatedAt time.Time
}

type TOTPFactor struct {
	UserID          string
	EncryptedSecret []byte
	Active          bool
	LastUsedStep    int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type RecoveryCode struct {
	UserID string
	Digest []byte
	UsedAt *time.Time
}

type Passkey struct {
	ID             string
	UserID         string
	Name           string
	CredentialID   []byte
	CredentialJSON []byte
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

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

type IssuedPAT struct {
	PAT   PAT
	Token string
}

type Authentication struct {
	UserID               string
	Method               AuthMethod
	Level                AssuranceLevel
	AuthenticatedAt      time.Time
	SecondFactorRequired bool
	WorkspaceID          string
	Scopes               []string
}

func (a Authentication) Interactive() bool {
	return a.Method == MethodPassword || a.Method == MethodTOTP || a.Method == MethodPasskey || a.Method == MethodSSO
}

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

type AuditOutcome string

const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditFailed    AuditOutcome = "failed"
)

type ActorKind string

const (
	ActorUser    ActorKind = "user"
	ActorService ActorKind = "service"
	ActorSystem  ActorKind = "system"
)

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
}

type SCIMGroupRoleMapping struct {
	ExternalID string
	Role       Role
	Priority   int
}

type SCIMConfiguration struct {
	ID                   string
	WorkspaceID          string
	Enabled              bool
	DefaultRole          Role
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

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

type IssuedSCIMCredential struct {
	Configuration SCIMConfiguration
	Credential    SCIMCredential
	Token         string
}

type SCIMAuthentication struct {
	ConfigurationID string
	WorkspaceID     string
	CredentialID    string
	AuthenticatedAt time.Time
}

type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

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

type CreateSCIMConfigurationInput struct {
	DefaultRole          Role
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
	CredentialExpiresAt  *time.Time
}

type UpdateSCIMConfigurationInput struct {
	DefaultRole          Role
	TrustDirectoryEmails bool
	GroupRoleMappings    []SCIMGroupRoleMapping
}

type SCIMUserInput struct {
	Schemas     []string
	ExternalID  string
	UserName    string
	DisplayName string
	Emails      []SCIMEmail
	Attributes  map[string]json.RawMessage
	Active      bool
}

type SCIMGroupInput struct {
	ExternalID  string
	DisplayName string
	MemberIDs   []string
}

type SCIMFilter struct {
	Attribute string
	Value     string
}

type AuditInput struct {
	Action       string
	ResourceType string
	ResourceID   string
	WorkspaceID  string
	Outcome      AuditOutcome
	Reason       string
}

type SSOProviderKind string

const (
	SSOProviderGoogle    SSOProviderKind = "google"
	SSOProviderGitHub    SSOProviderKind = "github"
	SSOProviderMicrosoft SSOProviderKind = "microsoft"
	SSOProviderOIDC      SSOProviderKind = "oidc"
	SSOProviderSAML      SSOProviderKind = "saml"
)

type SSORequest struct {
	ForceReauthentication bool
}

type SSOProviderChallenge struct {
	RedirectURL string
	Session     []byte
}

type SSOClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

type SSOChallenge struct {
	RedirectURL  string
	Continuation string
}

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

type PageRequest struct {
	Cursor string
	Limit  int
}

type PageEnd struct {
	NextCursor string `json:"next_cursor,omitempty"`
	HasMore    bool   `json:"has_more"`
}

type PageEvent[T any] struct {
	Type string   `json:"type"`
	Data *T       `json:"data,omitempty"`
	End  *PageEnd `json:"page_end,omitempty"`
}

func ItemEvent[T any](value T) PageEvent[T] {
	return PageEvent[T]{Type: "item", Data: &value}
}

func EndEvent[T any](end PageEnd) PageEvent[T] {
	return PageEvent[T]{Type: "page_end", End: &end}
}

type BootstrapInput struct {
	Email         string
	DisplayName   string
	Password      string
	WorkspaceName string
}

type CreateUserInput struct {
	Email       string
	DisplayName string
	Password    string
	Role        Role
}

type CreateWorkspaceInput struct {
	Name string
}

type UpdateWorkspaceInput struct {
	Name string
}

type TOTPEnrollment struct {
	URI string
}

type CreatePATInput struct {
	Name        string
	WorkspaceID string
	Scopes      []string
	ExpiresAt   *time.Time
}

type PasskeyChallenge struct {
	Options      json.RawMessage `json:"options"`
	Continuation string          `json:"continuation"`
}

type PasskeyUser struct {
	User        User
	Credentials func(yield func(Passkey, error) bool)
}
