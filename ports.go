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
	// UpdateUser persists the user's mutable profile fields. It returns
	// ErrNotFound for an unknown identifier.
	UpdateUser(context.Context, User, Commit) error
	UserByEmail(context.Context, string) (User, error)
	UserByID(context.Context, string) (User, error)
	Users(context.Context, PageRequest) iter.Seq2[PageEvent[User], error]
	PasswordByUserID(context.Context, string) (PasswordCredential, error)
	ReplacePassword(context.Context, PasswordCredential, Commit) error
	// RecordAuthentication updates last_seen_at and clears the user's login
	// throttle in the same transaction as its audit event.
	RecordAuthentication(context.Context, string, time.Time, Commit) error
	LoginThrottleByUserID(context.Context, string) (LoginThrottle, error)
	// RecordLoginFailure atomically increments the failure counter and, once
	// the counter reaches the threshold, persists the lockout deadline. It
	// returns the updated throttle.
	RecordLoginFailure(ctx context.Context, userID string, at time.Time, threshold int64, lockedUntil time.Time, commit Commit) (LoginThrottle, error)

	CreatePasswordReset(context.Context, PasswordResetCredential, Commit) error
	PasswordResetByID(context.Context, string) (PasswordResetCredential, error)
	// CompletePasswordReset atomically consumes the single-use reset,
	// replaces the password, deletes the user's other pending resets,
	// revokes the user's PATs and OAuth grants (and, for SessionStore-capable
	// stores, their sessions), and clears the login throttle. It returns
	// ErrConflict when the reset was already consumed.
	CompletePasswordReset(ctx context.Context, resetID string, password PasswordCredential, at time.Time, commit Commit) error

	CreateEmailAuthentication(context.Context, EmailAuthenticationCredential, Commit) error
	EmailAuthenticationByID(context.Context, string) (EmailAuthenticationCredential, error)
	// ConsumeEmailAuthentication atomically marks the single-use magic-link
	// token as used, updates last_seen_at and clears the login throttle. It
	// returns ErrConflict when the token was already consumed.
	ConsumeEmailAuthentication(ctx context.Context, tokenID, userID string, at time.Time, commit Commit) error

	SaveEmail(context.Context, EmailAddress, EmailVerificationCredential, Commit) error
	EmailVerificationByID(context.Context, string) (EmailAddress, EmailVerificationCredential, error)
	// EmailByAddress resolves an address to its record without the verification
	// credential; ErrNotFound when no address matches. ResendEmailVerification
	// uses it to find the pending address to re-issue.
	EmailByAddress(context.Context, string) (EmailAddress, error)
	// ReissueEmailVerification replaces the pending verification credential of
	// an unverified address; an already-verified or missing address reports
	// ErrConflict.
	ReissueEmailVerification(context.Context, string, EmailVerificationCredential, Commit) error
	VerifyEmail(context.Context, string, time.Time, Commit) error
	SetPrimaryEmail(context.Context, string, string, Commit) error
	RemoveEmail(context.Context, string, string, Commit) error
	Emails(context.Context, string, PageRequest) iter.Seq2[PageEvent[EmailAddress], error]

	TOTPByUserID(context.Context, string) (TOTPFactor, error)
	SaveTOTPEnrollment(context.Context, TOTPFactor, Commit) error
	ActivateTOTP(context.Context, TOTPFactor, []RecoveryCode, Commit) error
	UseTOTP(context.Context, string, int64, Commit) (bool, error)
	ConsumeRecoveryCode(context.Context, string, []byte, time.Time, Commit) (bool, error)
	CountUnusedRecoveryCodes(context.Context, string) (int64, error)
	DisableTOTP(context.Context, string, Commit) error
	// ReplaceRecoveryCodes atomically deletes the user's recovery codes and
	// inserts the replacement set. It returns ErrNotFound without an active
	// TOTP factor.
	ReplaceRecoveryCodes(ctx context.Context, userID string, codes []RecoveryCode, commit Commit) error
	// ResetSecondFactor atomically removes the user's TOTP factor with its
	// recovery codes and every passkey and, for SessionStore-capable
	// stores, revokes the user's sessions in the same transaction. It
	// succeeds even when the user has no second factor; an unknown user
	// reports ErrNotFound.
	ResetSecondFactor(ctx context.Context, userID string, at time.Time, commit Commit) error

	Passkeys(context.Context, string) iter.Seq2[Passkey, error]
	SavePasskey(context.Context, Passkey, Commit) error
	TouchPasskey(context.Context, string, []byte, []byte, time.Time, Commit) error
	DeletePasskey(context.Context, string, string, Commit) error

	CreatePAT(context.Context, PAT, Commit) error
	PATByPrefix(context.Context, string) (PAT, error)
	TouchPAT(context.Context, string, time.Time, Commit) error
	RevokePAT(context.Context, string, string, time.Time, Commit) error
	PATs(context.Context, string, PageRequest) iter.Seq2[PageEvent[PAT], error]
	// RevokeUserCredentials atomically revokes every active PAT of the user
	// and, when the store has the OAuth capability, every OAuth grant and its
	// tokens. A SessionStore-capable store also revokes the user's sessions
	// in the same transaction; sessions the host manages itself remain
	// host-owned and unaffected.
	RevokeUserCredentials(context.Context, string, time.Time, Commit) error
	// AnonymizeUser pseudonymizes a user in one transaction: it scrubs the
	// mutable personal data (display name, email addresses, SSO and PAT names,
	// session IP/User-Agent), disables the account, revokes its PATs, sessions
	// and (with the OAuth capability) grants, and removes its second factors.
	// The append-only audit chain is deliberately left intact. It reports
	// ErrConflict when the target is the last enabled root administrator or the
	// sole admin of a workspace, mirroring SetUserDisabled, and ErrNotFound for
	// an unknown user.
	AnonymizeUser(ctx context.Context, userID string, at time.Time, commit Commit) error

	CreateWorkspaceInvitation(context.Context, WorkspaceInvitation, Commit) error
	WorkspaceInvitationByID(context.Context, string) (WorkspaceInvitation, error)
	PendingWorkspaceInvitation(ctx context.Context, workspaceID, email string) (WorkspaceInvitation, error)
	// AcceptWorkspaceInvitation atomically marks the pending invitation
	// accepted by the user and upserts the membership. It returns
	// ErrConflict when the invitation was already accepted or revoked.
	AcceptWorkspaceInvitation(ctx context.Context, invitationID, userID string, at time.Time, membership Membership, commit Commit) error
	// RegisterInvitedUser atomically creates the invited account (user,
	// verified email, password, membership) and marks the invitation
	// accepted. It returns ErrConflict when the invitation was already
	// accepted or revoked.
	RegisterInvitedUser(ctx context.Context, invitationID string, user User, email EmailAddress, password PasswordCredential, membership Membership, at time.Time, commit Commit) error
	RevokeWorkspaceInvitation(ctx context.Context, workspaceID, invitationID string, at time.Time, commit Commit) error
	WorkspaceInvitations(context.Context, string, PageRequest) iter.Seq2[PageEvent[WorkspaceInvitation], error]

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
	// AuditChainHead returns the sequence and hash of the latest chained
	// audit event; sequence 0 with a 32-zero-byte hash for an empty chain.
	AuditChainHead(context.Context) (int64, []byte, error)
	// ChainedAuditEvents streams every chained audit event with a sequence
	// strictly greater than afterSequence, in ascending order, so the chain
	// can be recomputed from the genesis (0) or from a checkpoint.
	ChainedAuditEvents(ctx context.Context, afterSequence int64) iter.Seq2[AuditEvent, error]
}

// SignupStore is an optional persistence capability required by SignUp.
// CreateSignup atomically creates the user, their primary email address, the
// password credential, the workspace and the admin membership, or nothing at
// all. The verification credential is nil when the host auto-verifies the
// address (the email then carries VerifiedAt); otherwise the email starts
// unverified and the credential is persisted exactly as SaveEmail would,
// keyed by the email identifier, so ConfirmEmail completes the proof. A
// globally taken address fails with ErrConflict. Custom stores that do not
// implement it can continue to use every other feature of Credbound.
type SignupStore interface {
	CreateSignup(ctx context.Context, user User, email EmailAddress, verification *EmailVerificationCredential, password PasswordCredential, workspace Workspace, membership Membership, commit Commit) error
}

// SessionStore is an optional persistence capability required by the session
// operations (CreateSession, AuthenticateSession, Sessions, RevokeSession,
// RevokeUserSessions); without it every one of them returns ErrNotSupported.
//
// Cascade contract: a store implementing SessionStore must extend its
// CompletePasswordReset, SetUserDisabled (when disabling, not when
// re-enabling) and RevokeUserCredentials implementations to also stamp
// RevokedAt on the user's active sessions inside the same transaction, so a
// recovery or lockdown revokes interactive sessions atomically with the rest
// of the account's credentials. Stores without the capability keep their
// existing contracts; hosts then terminate their own sessions.
//
// Sessions never returns the token digest: listed Session values carry a nil
// Digest. SessionByID returns the digest for constant-time validation by the
// Manager, which scrubs it before results leave the library.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session, commit Commit) error
	SessionByID(ctx context.Context, id string) (Session, error)
	// TouchSession updates the session's last-seen timestamp (and the user's
	// last_seen_at) in the same transaction as its audit event.
	TouchSession(ctx context.Context, id string, at time.Time, commit Commit) error
	RevokeSession(ctx context.Context, id string, at time.Time, commit Commit) error
	// RevokeUserSessions stamps RevokedAt on every active session of the user.
	RevokeUserSessions(ctx context.Context, userID string, at time.Time, commit Commit) error
	Sessions(ctx context.Context, userID string, page PageRequest) iter.Seq2[PageEvent[Session], error]
}

// EmailThrottleStore is an optional persistence capability that backs the
// per-address cooldown on unauthenticated email-issuing flows (BeginPasswordReset,
// BeginEmailAuthentication, BeginEmailOTP, ResendEmailVerification). Without it,
// or with Config.EmailIssuanceCooldown left at zero, those flows are not
// throttled and the host is responsible for its own rate limiting.
type EmailThrottleStore interface {
	// ClaimEmailIssuance atomically records an issuance for (address, purpose)
	// at time `at` and reports whether it was allowed: it claims only when no
	// prior issuance for that pair is newer than notBefore. It is keyed by
	// address regardless of account existence, so it opens no enumeration
	// oracle, and it needs no audit commit — it is rate-limit bookkeeping.
	ClaimEmailIssuance(ctx context.Context, address, purpose string, at, notBefore time.Time) (bool, error)
}

// DomainStore is an optional persistence capability required by the
// workspace-domain operations (CreateWorkspaceDomain, ConfirmWorkspaceDomain,
// UpdateWorkspaceDomainPolicy, RemoveWorkspaceDomain, WorkspaceDomains), by
// domain-enforced SSO and by JIT provisioning; without it every domain
// operation returns ErrNotSupported and the authentication flows behave as if
// no domain existed.
//
// A domain name is globally unique across workspaces: CreateWorkspaceDomain
// fails with ErrConflict for a taken name. ConfirmWorkspaceDomain fails with
// ErrConflict when the domain was already confirmed, and
// UpdateWorkspaceDomainPolicy fails with ErrConflict on an unconfirmed
// domain, so the pending state never carries policy.
type DomainStore interface {
	CreateWorkspaceDomain(ctx context.Context, domain WorkspaceDomain, commit Commit) error
	WorkspaceDomainByID(ctx context.Context, id string) (WorkspaceDomain, error)
	// ConfirmedWorkspaceDomainByName is the hot lookup behind SSO enforcement
	// and JIT provisioning: it resolves a normalized domain name to its
	// confirmed record and returns ErrNotFound when the domain is absent or
	// not yet confirmed.
	ConfirmedWorkspaceDomainByName(ctx context.Context, domain string) (WorkspaceDomain, error)
	ConfirmWorkspaceDomain(ctx context.Context, id string, at time.Time, commit Commit) error
	UpdateWorkspaceDomainPolicy(ctx context.Context, id string, policy WorkspaceDomainPolicyInput, at time.Time, commit Commit) error
	DeleteWorkspaceDomain(ctx context.Context, id string, commit Commit) error
	WorkspaceDomains(ctx context.Context, workspaceID string, page PageRequest) iter.Seq2[PageEvent[WorkspaceDomain], error]
	// JITProvisionSSOUser atomically creates a passwordless user, their
	// verified primary email, the auto-join membership and the SSO identity
	// link, or nothing at all. A concurrently claimed address or identity
	// fails with ErrConflict.
	JITProvisionSSOUser(ctx context.Context, user User, email EmailAddress, membership Membership, identity SSOIdentity, at time.Time, commit Commit) error
}

// DomainVerifier optionally proves control of a workspace domain before
// ConfirmWorkspaceDomain marks it verified. Registered in Config.DomainVerifier,
// its VerifyDomain runs inside ConfirmWorkspaceDomain with the domain name and
// the challenge token minted at creation; any non-nil error refuses the
// confirmation with ErrDomainVerification. A typical implementation resolves
// the domain's TXT records and checks the challenge is published. Without a
// verifier, confirmation trusts the actor's out-of-band check — a self-serve
// deployment that exposes ConfirmWorkspaceDomain directly should register one,
// because a confirmed domain governs SSO enforcement and JIT provisioning for
// every address on it, instance-wide.
type DomainVerifier interface {
	VerifyDomain(ctx context.Context, domain, challenge string) error
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

// PasswordHasher derives and verifies password hashes. Verify additionally
// reports rehash when the stored hash uses outdated parameters, so a
// successful authentication can transparently renew it. Argon2id with
// versioned parameters is the intended implementation.
type PasswordHasher interface {
	Hash(string) (string, error)
	Verify(string, string) (match bool, rehash bool, err error)
}

// PasswordPolicy lets the host reject candidate passwords beyond the built-in
// length rules — typically against a breached-password corpus such as Have I
// Been Pwned via k-anonymity, per NIST 800-63B. Return an error wrapping
// ErrInvalidInput to reject the password; any other error is treated as an
// infrastructure failure and aborts the operation. The policy runs on every
// password acceptance path (bootstrap, user creation, change, reset, and
// invitation registration) and always after the built-in length validation.
// The candidate password must never be logged or persisted by implementations.
type PasswordPolicy interface {
	ValidatePassword(ctx context.Context, password string) error
}

// TOTPProvider is the optional time-based OTP algorithm port. Generate
// returns the shared secret and its otpauth:// URI; Validate reports the
// accepted time step so the store can reject replays of the same step.
type TOTPProvider interface {
	Generate(accountName string) (secret string, uri string, err error)
	Validate(code, secret string, at time.Time) (step int64, valid bool)
}

// PasskeyProvider is the optional WebAuthn ceremony port. Each Begin method
// returns the browser options and an opaque session that Credbound seals
// into the continuation; each Finish method validates the browser response
// against that session. Implementations must require user verification.
type PasskeyProvider interface {
	BeginRegistration(context.Context, PasskeyUser) (json.RawMessage, []byte, error)
	FinishRegistration(context.Context, PasskeyUser, []byte, []byte) (credentialID, credentialJSON []byte, err error)
	// BeginAuthentication starts an assertion ceremony over the user's stored
	// passkeys. It returns ErrNoPasskey when the user has none, which the
	// manager answers with a decoy so the response never reveals whether an
	// account has a passkey.
	BeginAuthentication(context.Context, PasskeyUser) (json.RawMessage, []byte, error)
	// BeginDecoyAuthentication produces an assertion challenge for an address
	// with no passkey (or no account), structurally indistinguishable from
	// BeginAuthentication. The seed makes the fabricated credential descriptors
	// stable for a given address, so repeated probes cannot tell a decoy from a
	// real challenge by its variation.
	BeginDecoyAuthentication(ctx context.Context, seed []byte) (json.RawMessage, []byte, error)
	FinishAuthentication(context.Context, PasskeyUser, []byte, []byte) (credentialID, credentialJSON []byte, err error)
}

// SSOProvider is the network adapter for one registered identity provider.
// ConfigurationID returns the stable UUIDv7 the host addresses it by, Begin
// starts a ceremony (honoring SSORequest.ForceReauthentication for
// step-up), and Finish validates the provider response against the sealed
// session and returns the asserted claims.
type SSOProvider interface {
	ConfigurationID() string
	Kind() SSOProviderKind
	Begin(context.Context, SSORequest) (SSOProviderChallenge, error)
	Finish(context.Context, []byte, []byte) (SSOClaims, error)
}

// Operation is one observed unit of work: an API call, a transaction hook or
// an event listener invocation. Outcome is "success", "error" or "panic".
// Names are low-cardinality and values never contain secrets.
type Operation struct {
	Name     string
	Outcome  string
	Duration time.Duration
}

// Observer receives Operation records for metrics, logs and traces (OTEL is
// the intended sink). Implementations must be safe for concurrent use.
type Observer interface {
	Observe(context.Context, Operation)
}

type nopObserver struct{}

func (nopObserver) Observe(context.Context, Operation) {}
