package credbound

import (
	"context"
	"encoding/json"
	"iter"
	"time"
)

// Store persists every mutation together with its transaction hooks and audit.
// Implementations must commit all three stages or none of them.
//
// Store is the required persistence port. It is composed of the capability
// groups below purely for navigability — the method set is unchanged and a
// Store implements all of them; the optional capabilities (SignupStore,
// SessionStore, EmailThrottleStore, DomainStore, SCIMStore, PrivacyStore,
// OAuthStore, PasskeyCredentialStore) remain separate interfaces.
//
// Compatibility contract: the required method set may grow in minor releases
// as features ship, so implementing Store from scratch means tracking every
// release. External stores that want to stay compile-compatible across
// upgrades should embed one of the shipped implementations (sqlstore/sqlite,
// sqlstore/postgresql, memory) in a struct and override only the methods
// they need.
type Store interface {
	IdentityStore
	PasswordResetStore
	EmailAuthenticationStore
	EmailStore
	TOTPStore
	PasskeyStore
	PATStore
	RevocationStore
	InvitationStore
	WorkspaceStore
	SSOLinkStore
	AuditStore
}

// IdentityStore is the account backbone of the required Store: user
// records, the password credential with its currency guards, and the
// login throttle.
type IdentityStore interface {
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
	// RehashPassword installs a stronger hash of the password that just
	// verified — the transparent-rehash path — but only while previousHash,
	// the stored hash the verification ran against, is still in place. When
	// a concurrent change or reset already replaced the credential it
	// returns ErrConflict and leaves the store untouched: an unconditional
	// swap here would let an in-flight sign-in resurrect the very password
	// the user just rotated away from.
	RehashPassword(ctx context.Context, password PasswordCredential, previousHash string, commit Commit) error
	// ChangePassword installs the user's new password for an authenticated
	// password change. Unlike RehashPassword, a SessionStore-capable store
	// must stamp RevokedAt on the user's active sessions in the same
	// transaction, so a failure leaves both the password and the sessions
	// untouched.
	ChangePassword(ctx context.Context, password PasswordCredential, at time.Time, commit Commit) error
	// RecordAuthentication updates last_seen_at and clears the user's login
	// throttle in the same transaction as its audit event.
	RecordAuthentication(context.Context, string, time.Time, Commit) error
	// RecordPasswordAuthentication finalizes a password sign-in like
	// RecordAuthentication, but only while currentHash is still the user's
	// stored password credential; the comparison and the finalization happen
	// in the same transaction. When a concurrent change or reset replaced the
	// credential — or removed it — it returns ErrConflict and leaves the
	// store untouched, so a sign-in that verified a password can never
	// complete after that password stopped being current.
	RecordPasswordAuthentication(ctx context.Context, userID, currentHash string, at time.Time, commit Commit) error
	LoginThrottleByUserID(context.Context, string) (LoginThrottle, error)
	// RecordLoginFailure atomically increments the failure counter and, once
	// the counter reaches the threshold, persists the lockout deadline. It
	// returns the updated throttle.
	RecordLoginFailure(ctx context.Context, userID string, at time.Time, threshold int64, lockedUntil time.Time, commit Commit) (LoginThrottle, error)
}

// PasswordResetStore persists the single-use password-reset credentials
// and the atomic reset completion with its revocation sweep.
type PasswordResetStore interface {
	CreatePasswordReset(context.Context, PasswordResetCredential, Commit) error
	PasswordResetByID(context.Context, string) (PasswordResetCredential, error)
	// CompletePasswordReset atomically consumes the single-use reset,
	// installs the password — replacing the previous one, or creating the
	// account's first for a passwordless member provisioned by SSO JIT or
	// SCIM — deletes the user's other pending resets, revokes the user's
	// PATs and OAuth grants (and, for SessionStore-capable stores, their
	// sessions), and clears the login throttle. It returns ErrConflict when
	// the reset was already consumed.
	CompletePasswordReset(ctx context.Context, resetID string, password PasswordCredential, at time.Time, commit Commit) error
}

// EmailAuthenticationStore persists the single-use magic-link and email
// OTP credentials.
type EmailAuthenticationStore interface {
	CreateEmailAuthentication(context.Context, EmailAuthenticationCredential, Commit) error
	EmailAuthenticationByID(context.Context, string) (EmailAuthenticationCredential, error)
	// ConsumeEmailAuthentication atomically marks the single-use magic-link
	// or email OTP token as used. When completesLogin is true it also
	// updates last_seen_at and clears the login throttle; a consumption
	// that leaves a second factor pending passes false so the completing
	// factor clears them on success. It returns ErrConflict when the token
	// was already consumed.
	ConsumeEmailAuthentication(ctx context.Context, tokenID, userID string, at time.Time, completesLogin bool, commit Commit) error
}

// EmailStore persists a user's email addresses and their verification
// credentials.
type EmailStore interface {
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
}

// TOTPStore persists the TOTP factor, its recovery codes, and the atomic
// second-factor reset.
type TOTPStore interface {
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
}

// PasskeyStore persists WebAuthn credentials. The optional
// PasskeyCredentialStore capability extends it for the usernameless flow.
type PasskeyStore interface {
	Passkeys(context.Context, string) iter.Seq2[Passkey, error]
	SavePasskey(context.Context, Passkey, Commit) error
	// TouchPasskey persists the credential's updated JSON and last-used time
	// after a successful assertion, updates last_seen_at and — the sign-in
	// completed (AUTH-009) — clears the login throttle.
	TouchPasskey(context.Context, string, []byte, []byte, time.Time, Commit) error
	DeletePasskey(context.Context, string, string, Commit) error
}

// PATStore persists personal access tokens.
type PATStore interface {
	CreatePAT(context.Context, PAT, Commit) error
	PATByPrefix(context.Context, string) (PAT, error)
	TouchPAT(context.Context, string, time.Time, Commit) error
	RevokePAT(context.Context, string, string, time.Time, Commit) error
	PATs(context.Context, string, PageRequest) iter.Seq2[PageEvent[PAT], error]
}

// RevocationStore holds the cross-credential compromise-response and
// privacy operations.
type RevocationStore interface {
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
	// A SCIMStore-capable store also scrubs the personal attributes of every
	// SCIM profile linked to the user (user name, display name, emails,
	// directory attributes) and marks it deprovisioned, and the email on
	// workspace invitations the user accepted is replaced with a tombstone.
	// The append-only audit chain is deliberately left intact. It reports
	// ErrConflict when the target is the last enabled root administrator or the
	// sole admin of a workspace, mirroring SetUserDisabled, and ErrNotFound for
	// an unknown user.
	AnonymizeUser(ctx context.Context, userID string, at time.Time, commit Commit) error
}

// InvitationStore persists workspace invitations and their atomic
// acceptance paths.
type InvitationStore interface {
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
}

// WorkspaceStore persists workspaces, memberships and instance role
// assignments.
type WorkspaceStore interface {
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
	// InstanceAdministrators streams every instance role assignment, oldest
	// first. The set is bounded by governance, not by end users, so it is
	// not paginated.
	InstanceAdministrators(context.Context) iter.Seq2[InstanceAdministrator, error]
	SetInstanceRole(context.Context, InstanceAdministrator, Commit) error
	RemoveInstanceRole(context.Context, string, Commit) error
}

// SSOLinkStore persists the links between accounts and external SSO
// identities.
type SSOLinkStore interface {
	SSOIdentity(context.Context, string, string, string) (SSOIdentity, error)
	// LinkSSO stores a new SSO identity link; an identity already linked to
	// any user reports ErrConflict. A link carrying LastUsedAt records a
	// completed sign-in, so it also updates last_seen_at and clears the
	// login throttle (AUTH-009).
	LinkSSO(context.Context, SSOIdentity, Commit) error
	// TouchSSO updates the identity's last-used time after a successful SSO
	// login, updates last_seen_at and — the sign-in completed (AUTH-009) —
	// clears the login throttle.
	TouchSSO(context.Context, string, string, time.Time, Commit) error
	// UnlinkSSO removes one linked identity, refusing with ErrConflict when
	// it is the user's last remaining authentication method (no password
	// credential, no passkey, no other SSO identity) — a JIT-provisioned,
	// passwordless member must not be able to lock themselves out.
	UnlinkSSO(context.Context, string, string, Commit) error
	SSOIdentities(context.Context, string, PageRequest) iter.Seq2[PageEvent[SSOIdentity], error]
}

// AuditStore persists the append-only audit trail and its hash chain.
type AuditStore interface {
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
// CompletePasswordReset, ChangePassword, SetUserDisabled (when disabling, not
// when re-enabling) and RevokeUserCredentials implementations to also stamp
// RevokedAt on the user's active sessions inside the same transaction, so a
// recovery or lockdown revokes interactive sessions atomically with the rest
// of the account's credentials. Stores without the capability keep their
// existing contracts; hosts then terminate their own sessions.
//
// Sessions never returns the token digest: listed Session values carry a nil
// Digest. SessionByID returns the digest for constant-time validation by the
// Manager, which scrubs it before results leave the library.
type SessionStore interface {
	// CreateSession stores a server-side session. A non-empty
	// credentialDigest is the currency guard: inside the same transaction the
	// store recomputes CredentialFingerprint over the user's current password
	// credential hash and returns ErrConflict when it no longer matches (or
	// the credential vanished), so an Authentication whose password was
	// concurrently replaced cannot mint a session that would survive the
	// replacement's revocation sweep. An empty digest skips the guard — the
	// context was not produced by a password.
	CreateSession(ctx context.Context, session Session, credentialDigest []byte, commit Commit) error
	SessionByID(ctx context.Context, id string) (Session, error)
	// TouchSession refuses a session already revoked with ErrConflict, so an
	// authentication racing a revocation can neither record activity on nor
	// extend the idle window of a dead session; otherwise it
	// updates the session's last-seen timestamp (and the user's
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
	// prior issuance for that pair is newer than notBefore. The address the
	// manager passes is an opaque, fixed-size HMAC key derived from the
	// normalized address — never the address itself — so rows stay bounded
	// and the store learns nothing about the addresses tried. Entries with
	// last_issued_at at or before notBefore no longer throttle anything, and
	// implementations prune them on each claim so anonymous traffic cannot
	// grow the bookkeeping beyond the current cooldown window. It is keyed
	// regardless of account existence, so it opens no enumeration oracle,
	// and it needs no audit commit — it is rate-limit bookkeeping.
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
// fails with ErrConflict for a taken name, except that it replaces — in the
// same transaction — a stale pending claim, one still unconfirmed and created
// before staleBefore, so an unverified claim can never permanently deny the
// domain's real owner (Config.DomainClaimTTL sets the window). Confirmed
// domains never expire. ConfirmWorkspaceDomain fails with ErrConflict when
// the domain was already confirmed, and UpdateWorkspaceDomainPolicy fails
// with ErrConflict on an unconfirmed domain, so the pending state never
// carries policy.
type DomainStore interface {
	CreateWorkspaceDomain(ctx context.Context, domain WorkspaceDomain, staleBefore time.Time, commit Commit) error
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
// verifier, ConfirmWorkspaceDomain refuses with ErrNotSupported unless
// Config.TrustActorDomainVerification explicitly opts into trusting the
// actor's out-of-band check — a dangerous setting wherever the operation is
// reachable from self-serve actors, because a confirmed domain governs SSO
// enforcement and JIT provisioning for every address on it, instance-wide.
type DomainVerifier interface {
	VerifyDomain(ctx context.Context, domain, challenge string) error
}

// SCIMStore is an optional persistence capability. Custom stores that do not
// implement it can continue to use every non-SCIM feature of Credbound.
type SCIMStore interface {
	CreateSCIMConfiguration(context.Context, SCIMConfiguration, SCIMCredential, Commit) error
	SCIMConfiguration(context.Context, string) (SCIMConfiguration, error)
	// SCIMConfigurations streams the workspace's provisioning domains,
	// oldest first. A workspace holds few configurations, so the stream is
	// not paginated.
	SCIMConfigurations(context.Context, string) iter.Seq2[SCIMConfiguration, error]
	UpdateSCIMConfiguration(context.Context, SCIMConfiguration, []Membership, Commit) error
	SCIMConfigurationByCredentialPrefix(context.Context, string) (SCIMConfiguration, SCIMCredential, error)
	// SCIMCredentials streams the configuration's bearer credentials, oldest
	// first, with digests omitted.
	SCIMCredentials(context.Context, string) iter.Seq2[SCIMCredential, error]
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

// PrivacyStore is an optional persistence capability that extends the
// data-subject primitives beyond the core account records. ExportUserData
// includes SCIM profiles and accepted workspace invitations only on a
// PrivacyStore-capable store; the first-party stores all implement it.
// Custom stores that skip it keep every other feature.
type PrivacyStore interface {
	// SCIMUsersByUser streams every tenant-scoped SCIM profile linked to
	// the user, across configurations, oldest first.
	SCIMUsersByUser(context.Context, string) iter.Seq2[SCIMUser, error]
	// AcceptedWorkspaceInvitations streams every workspace invitation the
	// user accepted, oldest first, with digests included; readers exporting
	// them must scrub the Digest.
	AcceptedWorkspaceInvitations(context.Context, string) iter.Seq2[WorkspaceInvitation, error]
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
	// RotateOAuthClientCredentials atomically replaces the client's secret
	// digest and/or inline JWKS (with its recomputed metadata hash) after an
	// administrative credential rotation; a nil secretDigest keeps the
	// current secret and a nil jwks keeps the current key set.
	RotateOAuthClientCredentials(ctx context.Context, id string, secretDigest, jwks, metadataHash []byte, at time.Time, commit Commit) error
	OAuthClientByID(context.Context, string) (OAuthClient, error)
	OAuthClientByClientID(context.Context, string, string) (OAuthClient, error)
	OAuthClients(context.Context, string, PageRequest) iter.Seq2[PageEvent[OAuthClient], error]
	CreateOAuthInitialAccessToken(context.Context, OAuthInitialAccessToken, Commit) error
	OAuthInitialAccessTokenByPrefix(context.Context, string) (OAuthInitialAccessToken, error)
	// OAuthInitialAccessTokens streams the issuer's DCR bootstrap
	// credentials, oldest first, revoked ones included and digests omitted.
	OAuthInitialAccessTokens(context.Context, string) iter.Seq2[OAuthInitialAccessToken, error]
	RevokeOAuthInitialAccessToken(context.Context, string, time.Time, Commit) error

	CreateOAuthGrantAndCode(context.Context, OAuthGrant, OAuthAuthorizationCode, Commit) error
	OAuthGrant(context.Context, string) (OAuthGrant, error)
	RevokeOAuthGrant(context.Context, string, time.Time, Commit) error
	OAuthGrants(context.Context, string, string, PageRequest) iter.Seq2[PageEvent[OAuthGrant], error]
	OAuthAuthorizationCodeByPrefix(context.Context, string) (OAuthAuthorizationCode, error)
	ConsumeOAuthAuthorizationCode(context.Context, string, time.Time, OAuthAccessToken, *OAuthRefreshToken, Commit) error
	OAuthAccessTokenByPrefix(context.Context, string) (OAuthAccessToken, error)
	// CreateOAuthClientAccessToken persists a client-credentials access token
	// (machine-to-machine, no user subject); OAuthClientAccessTokenByPrefix
	// resolves one for AuthenticateOAuthAccessToken, and
	// RevokeOAuthClientAccessToken stamps one revoked for RevokeOAuthToken.
	CreateOAuthClientAccessToken(context.Context, OAuthClientAccessToken, Commit) error
	OAuthClientAccessTokenByPrefix(context.Context, string) (OAuthClientAccessToken, error)
	RevokeOAuthClientAccessToken(context.Context, string, time.Time, Commit) error
	OAuthRefreshTokenByPrefix(context.Context, string) (OAuthRefreshToken, error)
	RotateOAuthRefreshToken(context.Context, string, time.Time, OAuthAccessToken, OAuthRefreshToken, Commit) error
	RevokeOAuthAccessToken(context.Context, string, time.Time, Commit) error
	// RevokeOAuthRefreshFamily stamps RevokedAt on every token of the
	// refresh-token family and on the access tokens of the grants the
	// family descends from, so a detected reuse (or an RFC 7009 refresh
	// revocation) leaves no derived bearer credential alive.
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

// PasskeyUserLookup resolves the account owning a credential ID during a
// discoverable ceremony. It reports ErrNotFound for an unknown credential.
type PasskeyUserLookup func(ctx context.Context, credentialID []byte) (PasskeyUser, error)

// DiscoverablePasskeyProvider is an optional extension of PasskeyProvider
// enabling usernameless (discoverable-credential) authentication: the
// ceremony starts with an empty allowCredentials list, so no per-address
// challenge exists to enumerate — the full fix for the residual
// allowCredentials-count signal the per-address decoy cannot close.
type DiscoverablePasskeyProvider interface {
	// BeginDiscoverableAuthentication starts an assertion ceremony bound to
	// no account; the authenticator offers its resident credentials.
	BeginDiscoverableAuthentication(context.Context) (json.RawMessage, []byte, error)
	// FinishDiscoverableAuthentication validates the browser response,
	// resolving the account through the lookup and verifying the asserted
	// user handle belongs to it.
	FinishDiscoverableAuthentication(ctx context.Context, session, response []byte, lookup PasskeyUserLookup) (credentialID, credentialJSON []byte, err error)
}

// PasskeyCredentialStore is an optional persistence capability required by
// discoverable passkey authentication: a global credential-ID lookup, which
// the per-user Passkeys stream cannot provide.
type PasskeyCredentialStore interface {
	// PasskeyByCredentialID returns the passkey owning the credential ID,
	// or ErrNotFound.
	PasskeyByCredentialID(ctx context.Context, credentialID []byte) (Passkey, error)
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
