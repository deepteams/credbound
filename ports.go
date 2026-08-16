package credbound

import (
	"context"
	"encoding/json"
	"iter"
	"time"
)

// Store persists every mutation together with its transaction hooks and audit.
// Implementations must commit all three stages or none of them.
type Store interface {
	Bootstrap(context.Context, User, EmailAddress, PasswordCredential, Workspace, Membership, InstanceAdministrator, Commit) error
	CreateUser(context.Context, User, EmailAddress, PasswordCredential, Membership, Commit) error
	SetUserDisabled(context.Context, string, bool, time.Time, Commit) error
	UserByEmail(context.Context, string) (User, error)
	UserByID(context.Context, string) (User, error)
	Users(context.Context, PageRequest) iter.Seq2[PageEvent[User], error]
	PasswordByUserID(context.Context, string) (PasswordCredential, error)
	ReplacePassword(context.Context, PasswordCredential, Commit) error
	RecordAuthentication(context.Context, string, time.Time, Commit) error

	SaveEmail(context.Context, EmailAddress, EmailVerificationCredential, Commit) error
	EmailVerificationByID(context.Context, string) (EmailAddress, EmailVerificationCredential, error)
	VerifyEmail(context.Context, string, time.Time, Commit) error
	SetPrimaryEmail(context.Context, string, string, Commit) error
	RemoveEmail(context.Context, string, string, Commit) error
	Emails(context.Context, string, PageRequest) iter.Seq2[PageEvent[EmailAddress], error]

	TOTPByUserID(context.Context, string) (TOTPFactor, error)
	SaveTOTPEnrollment(context.Context, TOTPFactor, Commit) error
	ActivateTOTP(context.Context, TOTPFactor, []RecoveryCode, Commit) error
	UseTOTP(context.Context, string, int64, Commit) (bool, error)
	ConsumeRecoveryCode(context.Context, string, []byte, time.Time, Commit) (bool, error)
	DisableTOTP(context.Context, string, Commit) error

	Passkeys(context.Context, string) iter.Seq2[Passkey, error]
	SavePasskey(context.Context, Passkey, Commit) error
	TouchPasskey(context.Context, string, []byte, []byte, time.Time, Commit) error
	DeletePasskey(context.Context, string, string, Commit) error

	CreatePAT(context.Context, PAT, Commit) error
	PATByPrefix(context.Context, string) (PAT, error)
	TouchPAT(context.Context, string, time.Time, Commit) error
	RevokePAT(context.Context, string, string, time.Time, Commit) error
	PATs(context.Context, string, PageRequest) iter.Seq2[PageEvent[PAT], error]

	CreateWorkspace(context.Context, Workspace, Membership, Commit) error
	WorkspaceByID(context.Context, string) (Workspace, error)
	UpdateWorkspace(context.Context, Workspace, Commit) error
	SetWorkspaceDisabled(context.Context, string, bool, time.Time, Commit) error
	Workspaces(context.Context, PageRequest) iter.Seq2[PageEvent[Workspace], error]
	UserWorkspaces(context.Context, string, PageRequest) iter.Seq2[PageEvent[Workspace], error]
	Membership(context.Context, string, string) (Membership, error)
	UpsertMembership(context.Context, Membership, Commit) error
	RemoveMembership(context.Context, string, string, time.Time, Commit) error
	Memberships(context.Context, string, PageRequest) iter.Seq2[PageEvent[Membership], error]
	InstanceAdministrator(context.Context, string) (InstanceAdministrator, error)
	SetInstanceRole(context.Context, InstanceAdministrator, Commit) error
	RemoveInstanceRole(context.Context, string, Commit) error

	SSOIdentity(context.Context, string, string, string) (SSOIdentity, error)
	LinkSSO(context.Context, SSOIdentity, Commit) error
	TouchSSO(context.Context, string, string, time.Time, Commit) error
	UnlinkSSO(context.Context, string, string, Commit) error
	SSOIdentities(context.Context, string, PageRequest) iter.Seq2[PageEvent[SSOIdentity], error]

	AppendAudit(context.Context, Commit) error
	AuditEvents(context.Context, string, PageRequest) iter.Seq2[PageEvent[AuditEvent], error]
	InstanceAuditEvents(context.Context, PageRequest) iter.Seq2[PageEvent[AuditEvent], error]
}

// SCIMStore is an optional persistence capability. Custom stores that do not
// implement it can continue to use every non-SCIM feature of Credbound.
type SCIMStore interface {
	CreateSCIMConfiguration(context.Context, SCIMConfiguration, SCIMCredential, Commit) error
	SCIMConfiguration(context.Context, string) (SCIMConfiguration, error)
	UpdateSCIMConfiguration(context.Context, SCIMConfiguration, []Membership, Commit) error
	SCIMConfigurationByCredentialPrefix(context.Context, string) (SCIMConfiguration, SCIMCredential, error)
	SaveSCIMCredential(context.Context, SCIMCredential, Commit) error
	RevokeSCIMCredential(context.Context, string, string, time.Time, Commit) error
	TouchSCIMCredential(context.Context, string, time.Time, Commit) error
	DisableSCIMConfiguration(context.Context, string, time.Time, Commit) error

	CreateSCIMUser(context.Context, User, EmailAddress, Membership, SCIMUser, Commit) error
	AdoptSCIMUser(context.Context, Membership, SCIMUser, Commit) error
	SCIMUser(context.Context, string, string) (SCIMUser, error)
	SCIMUserByExternalID(context.Context, string, string) (SCIMUser, error)
	SCIMUserByUserName(context.Context, string, string) (SCIMUser, error)
	UpdateSCIMUser(context.Context, SCIMUser, Membership, bool, Commit) error
	SCIMUsers(context.Context, string, SCIMFilter, PageRequest) iter.Seq2[PageEvent[SCIMUser], error]

	UpsertSCIMGroup(context.Context, SCIMGroup, []Membership, Commit) error
	SCIMGroup(context.Context, string, string) (SCIMGroup, error)
	SCIMGroupByExternalID(context.Context, string, string) (SCIMGroup, error)
	DeleteSCIMGroup(context.Context, SCIMGroup, []Membership, Commit) error
	SCIMGroups(context.Context, string, SCIMFilter, PageRequest) iter.Seq2[PageEvent[SCIMGroup], error]
}

// OAuthStore is an optional persistence capability. OAuth operations return
// ErrNotSupported unless both Config.OAuth and this store capability exist.
type OAuthStore interface {
	CreateOAuthIssuer(context.Context, OAuthIssuer, Commit) error
	UpdateOAuthIssuer(context.Context, OAuthIssuer, Commit) error
	SetOAuthIssuerDisabled(context.Context, string, bool, time.Time, Commit) error
	OAuthIssuerByID(context.Context, string) (OAuthIssuer, error)
	OAuthIssuerByURL(context.Context, string) (OAuthIssuer, error)
	OAuthIssuers(context.Context, PageRequest) iter.Seq2[PageEvent[OAuthIssuer], error]
	CreateOAuthProtectedResource(context.Context, OAuthProtectedResource, Commit) error
	SetOAuthProtectedResourceDisabled(context.Context, string, bool, time.Time, Commit) error
	OAuthProtectedResourceByID(context.Context, string) (OAuthProtectedResource, error)
	OAuthProtectedResourceByURI(context.Context, string) (OAuthProtectedResource, error)
	OAuthProtectedResources(context.Context, string, PageRequest) iter.Seq2[PageEvent[OAuthProtectedResource], error]

	CreateOAuthClient(context.Context, OAuthClient, string, time.Time, Commit) error
	UpsertOAuthCIMDClient(context.Context, OAuthClient, Commit) error
	SetOAuthClientDisabled(context.Context, string, bool, time.Time, Commit) error
	OAuthClientByID(context.Context, string) (OAuthClient, error)
	OAuthClientByClientID(context.Context, string, string) (OAuthClient, error)
	OAuthClients(context.Context, string, PageRequest) iter.Seq2[PageEvent[OAuthClient], error]
	CreateOAuthInitialAccessToken(context.Context, OAuthInitialAccessToken, Commit) error
	OAuthInitialAccessTokenByPrefix(context.Context, string) (OAuthInitialAccessToken, error)
	RevokeOAuthInitialAccessToken(context.Context, string, time.Time, Commit) error

	CreateOAuthGrantAndCode(context.Context, OAuthGrant, OAuthAuthorizationCode, Commit) error
	OAuthGrant(context.Context, string) (OAuthGrant, error)
	RevokeOAuthGrant(context.Context, string, time.Time, Commit) error
	OAuthGrants(context.Context, string, string, PageRequest) iter.Seq2[PageEvent[OAuthGrant], error]
	OAuthAuthorizationCodeByPrefix(context.Context, string) (OAuthAuthorizationCode, error)
	ConsumeOAuthAuthorizationCode(context.Context, string, time.Time, OAuthAccessToken, *OAuthRefreshToken, Commit) error
	OAuthAccessTokenByPrefix(context.Context, string) (OAuthAccessToken, error)
	OAuthRefreshTokenByPrefix(context.Context, string) (OAuthRefreshToken, error)
	RotateOAuthRefreshToken(context.Context, string, time.Time, OAuthAccessToken, OAuthRefreshToken, Commit) error
	RevokeOAuthAccessToken(context.Context, string, time.Time, Commit) error
	RevokeOAuthRefreshFamily(context.Context, string, time.Time, Commit) error
}

type PasswordHasher interface {
	Hash(string) (string, error)
	Verify(string, string) (match bool, rehash bool, err error)
}

type TOTPProvider interface {
	Generate(accountName string) (secret string, uri string, err error)
	Validate(code, secret string, at time.Time) (step int64, valid bool)
}

type PasskeyProvider interface {
	BeginRegistration(context.Context, PasskeyUser) (json.RawMessage, []byte, error)
	FinishRegistration(context.Context, PasskeyUser, []byte, []byte) (credentialID, credentialJSON []byte, err error)
	BeginAuthentication(context.Context, PasskeyUser) (json.RawMessage, []byte, error)
	FinishAuthentication(context.Context, PasskeyUser, []byte, []byte) (credentialID, credentialJSON []byte, err error)
}

type SSOProvider interface {
	ConfigurationID() string
	Kind() SSOProviderKind
	Begin(context.Context, SSORequest) (SSOProviderChallenge, error)
	Finish(context.Context, []byte, []byte) (SSOClaims, error)
}

type Operation struct {
	Name     string
	Outcome  string
	Duration time.Duration
}

type Observer interface {
	Observe(context.Context, Operation)
}

type nopObserver struct{}

func (nopObserver) Observe(context.Context, Operation) {}
