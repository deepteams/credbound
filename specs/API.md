# Public Go API

Credbound starts no HTTP server. Its normative core API is the Go API. Optional
`oauthhttp` and `scimhttp` packages expose handlers only when a host service
mounts them. The concrete OAuth/MCP adapter contract is documented in
[`oauthhttp.openapi.yaml`](oauthhttp.openapi.yaml); application-specific admin,
session, login, and consent APIs remain host contracts.

## Construction

```go
auth, err := credbound.New(credbound.Config{
    Store:          store,
    Passwords:      passwords,
    TOTP:           totpProvider,
    Passkeys:       passkeyProvider,
    SecretKey:      encryptionKey,
    PATPepper:      patPepper,
    RecoveryPepper: recoveryPepper,
    OAuth: &credbound.OAuthConfig{
        Pepper:          oauthPepper,
        MetadataFetcher: cimdFetcher,
        OIDCSigner:      oidcSigner,
    },
    StepUpMaxAge:   10 * time.Minute,
    WorkspaceRoles: []credbound.RoleDefinition{
        {
            Role:        "viewer",
            Permissions: []credbound.WorkspacePermission{"documents.read"},
        },
        {
            Role:        "editor",
            Permissions: []credbound.WorkspacePermission{"documents.write"},
            Inherits:    []credbound.Role{"viewer"},
        },
    },
    TransactionHooks: []credbound.TransactionHook{billingHook},
    EventListeners:   []credbound.EventListener{segmentListener},
})
```

`New` validates every configuration invariant. Cryptographic values have no
weak fallback. `RetiredSecretKeys`, `RetiredPATPeppers`, and
`RetiredRecoveryPeppers` form the read ring that keeps data issued before a
rotation readable while every write uses the active key.

## Main types

- `User`, `Workspace`, `Membership`: identity and tenant.
- `RoleDefinition`, `WorkspacePermission`: immutable workspace RBAC catalog.
- `EmailAddress`, `IssuedEmailVerification`: multiple addresses and verification proof.
- `SSOIdentity`, `SSOChallenge`: external identity linking and ceremony.
- `Authentication`: user, method, assurance level, and authentication time.
- `PAT`: persisted metadata without the secret.
- `IssuedPAT`: metadata and raw token, returned only by `CreatePAT`.
- `TOTPStatus`: enrollment state and unused recovery-code count, never the secret.
- `LoginThrottle`: per-user failure counter and lockout deadline.
- `PasswordResetCredential`, `IssuedPasswordReset`: single-use recovery proof;
  the raw token is returned only by `BeginPasswordReset`.
- `EmailAuthenticationCredential`, `IssuedEmailAuthentication`: single-use
  magic-link proof; the raw token is returned only by `BeginEmailAuthentication`.
- `WorkspaceInvitation`, `IssuedWorkspaceInvitation`: pending invitation and
  its raw token, returned only by `InviteToWorkspace`.
- `RequestMetadata`: sanitized client IP address and user agent that the host
  attaches with `WithRequestMetadata` for auditing.
- `AuditChainReport`: result of a successful `VerifyAuditChain`.
- `AuditEvent`: append-only entry.
- `SCIMConfiguration`, `SCIMCredential`, `SCIMAuthentication`: provisioning
  domain and service identity.
- `SCIMUser`, `SCIMGroup`, `SCIMFilter`: tenant-scoped resources and SCIM filtering.
- `OAuthIssuer`, `OAuthProtectedResource`, `OAuthClient`: authorization-server
  configuration, MCP resource, and application identity.
- `OAuthConsent`, `OAuthGrant`, `OAuthAuthentication`: sealed consent,
  persisted delegation, and validated bearer capability.
- `OAuthInitialAccessToken`, `OAuthTokenResponse`, `OIDCUserInfo`: DCR bootstrap,
  token-endpoint response, and minimal OIDC claims.
- `EventMeta`: UUIDv7 identity, name, operation, actor, workspace, and associated audit.
- `Tx` and `Commit`: transactional mutation capability and envelope.
- `PageRequest` and `PageEnd`: opaque-cursor pagination.

## Operations

```go
Bootstrap(ctx, BootstrapInput) (Authentication, Workspace, error)
CreateWorkspace(ctx, authn, CreateWorkspaceInput) (Workspace, error)
UpdateWorkspace(ctx, authn, workspaceID, UpdateWorkspaceInput) (Workspace, error)
DisableWorkspace(ctx, authn, workspaceID) error
EnableWorkspace(ctx, authn, workspaceID) error
AdminUpdateWorkspace(ctx, authn, TrustedRequest, workspaceID, UpdateWorkspaceInput) (Workspace, error)
AdminDisableWorkspace(ctx, authn, TrustedRequest, workspaceID) error
AdminEnableWorkspace(ctx, authn, TrustedRequest, workspaceID) error
CreateUser(ctx, authn, workspaceID, CreateUserInput) (User, error)
UpdateUser(ctx, authn, UpdateUserInput) (User, error)
DisableUser(ctx, authn, TrustedRequest, userID) error
EnableUser(ctx, authn, TrustedRequest, userID) error
AdminUpdateUser(ctx, authn, TrustedRequest, userID, UpdateUserInput) (User, error)
AddMembership(ctx, authn, workspaceID, userID, role) (Membership, error)
SetMembershipStatus(ctx, authn, workspaceID, userID, status) (Membership, error)
RemoveMembership(ctx, authn, workspaceID, userID) error
User(ctx, authn, userID) (User, error)
Users(ctx, authn, PageRequest) iter.Seq2[PageEvent[User], error]
Workspace(ctx, authn, workspaceID) (Workspace, error)
Workspaces(ctx, authn, PageRequest) iter.Seq2[PageEvent[Workspace], error]
UserWorkspaces(ctx, authn, PageRequest) iter.Seq2[PageEvent[Workspace], error]
Membership(ctx, authn, workspaceID, userID) (Membership, error)
Memberships(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[Membership], error]
AuthenticatePassword(ctx, email, password) (Authentication, error)
ChangePassword(ctx, authn, currentPassword, newPassword) error
BeginPasswordReset(ctx, email) (IssuedPasswordReset, error)
CompletePasswordReset(ctx, resetToken, newPassword) (User, error)
BeginEmailAuthentication(ctx, email) (IssuedEmailAuthentication, error)
CompleteEmailAuthentication(ctx, linkToken) (Authentication, error)
BeginEmailOTP(ctx, email) (IssuedEmailOTP, error)
CompleteEmailOTP(ctx, continuation, code) (Authentication, error)
SignUp(ctx, SignUpInput) (SignUpResult, error)

CreateSession(ctx, authn, CreateSessionInput) (IssuedSession, error)
AuthenticateSession(ctx, sessionToken) (Authentication, Session, error)
SignOut(ctx, sessionToken) error
Sessions(ctx, authn, userID, PageRequest) iter.Seq2[PageEvent[Session], error]
RevokeSession(ctx, authn, sessionID) error
RevokeUserSessions(ctx, authn, TrustedRequest, userID) error

CreateWorkspaceDomain(ctx, authn, workspaceID, domain) (IssuedWorkspaceDomain, error)
ConfirmWorkspaceDomain(ctx, authn, domainID) error
UpdateWorkspaceDomainPolicy(ctx, authn, domainID, WorkspaceDomainPolicyInput) error
RemoveWorkspaceDomain(ctx, authn, domainID) error
WorkspaceDomains(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[WorkspaceDomain], error]
RevokeUserCredentials(ctx, authn, TrustedRequest, userID) error
AdminResetSecondFactor(ctx, authn, TrustedRequest, userID) error

ExportUserData(ctx, authn, userID) (UserDataExport, error)
AnonymizeUser(ctx, authn, TrustedRequest, userID) error

BeginEmailAddition(ctx, authn, email) (IssuedEmailVerification, error)
ConfirmEmail(ctx, verificationToken) (EmailAddress, error)
ResendEmailVerification(ctx, email) (IssuedEmailVerification, error)
SetPrimaryEmail(ctx, authn, emailID) error
RemoveEmail(ctx, authn, emailID) error
Emails(ctx, authn, userID, PageRequest) iter.Seq2[PageEvent[EmailAddress], error]

BeginTOTPEnrollment(ctx, authn) (TOTPEnrollment, error)
ConfirmTOTPEnrollment(ctx, authn, code) ([]string, error)
VerifyTOTP(ctx, authn, code) (Authentication, error)
DisableTOTP(ctx, authn, code) error
RegenerateRecoveryCodes(ctx, authn) ([]string, error)
TOTPStatus(ctx, authn, userID) (TOTPStatus, error)

BeginPasskeyRegistration(ctx, authn, name) (PasskeyChallenge, error)
FinishPasskeyRegistration(ctx, authn, continuation, response) (Passkey, error)
BeginPasskeyAuthentication(ctx, email) (PasskeyChallenge, error)
FinishPasskeyAuthentication(ctx, continuation, response) (Authentication, error)
BeginDiscoverablePasskeyAuthentication(ctx) (PasskeyChallenge, error)
FinishDiscoverablePasskeyAuthentication(ctx, continuation, response) (Authentication, error)
DeletePasskey(ctx, authn, passkeyID) error
Passkeys(ctx, authn, userID) iter.Seq2[Passkey, error]

BeginSSO(ctx, providerConfigurationID) (SSOChallenge, error)
BeginSSOLink(ctx, authn, providerConfigurationID) (SSOChallenge, error)
BeginSSOStepUp(ctx, authn, providerConfigurationID) (SSOChallenge, error)
FinishSSO(ctx, continuation, response) (Authentication, error)
UnlinkSSO(ctx, authn, identityID) error
SSOIdentities(ctx, authn, userID, PageRequest) iter.Seq2[PageEvent[SSOIdentity], error]

RequireStepUp(authn) error

CreatePAT(ctx, authn, CreatePATInput) (IssuedPAT, error)
AuthenticatePAT(ctx, rawToken) (Authentication, error)
RevokePAT(ctx, authn, patID) error
PATs(ctx, authn, userID, PageRequest) iter.Seq2[PageEvent[PAT], error]

GrantRole(ctx, authn, workspaceID, userID, role) error
InviteToWorkspace(ctx, authn, workspaceID, InviteToWorkspaceInput) (IssuedWorkspaceInvitation, error)
AcceptInvitation(ctx, authn, invitationToken) (Membership, error)
RegisterFromInvitation(ctx, invitationToken, RegisterFromInvitationInput) (Authentication, User, error)
RevokeInvitation(ctx, authn, workspaceID, invitationID) error
WorkspaceInvitations(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[WorkspaceInvitation], error]
Authorize(ctx, authn, workspaceID, minimumRole) error
AuthorizePermission(ctx, authn, workspaceID, permission) error

CreateSCIMConfiguration(ctx, authn, workspaceID, CreateSCIMConfigurationInput) (IssuedSCIMCredential, error)
UpdateSCIMConfiguration(ctx, authn, configurationID, UpdateSCIMConfigurationInput) (SCIMConfiguration, error)
RotateSCIMCredential(ctx, authn, configurationID, expiresAt) (IssuedSCIMCredential, error)
RevokeSCIMCredential(ctx, authn, configurationID, credentialID) error
DisableSCIMConfiguration(ctx, authn, configurationID) error
AuthenticateSCIM(ctx, rawToken) (SCIMAuthentication, error)
AdoptSCIMUser(ctx, authn, configurationID, userID, SCIMUserInput) (SCIMUser, error)
ProvisionSCIMUser(ctx, scimAuthn, SCIMUserInput) (SCIMUser, error)
ReplaceSCIMUser(ctx, scimAuthn, scimUserID, SCIMUserInput) (SCIMUser, error)
DeprovisionSCIMUser(ctx, scimAuthn, scimUserID) error
SCIMUser(ctx, scimAuthn, scimUserID) (SCIMUser, error)
SCIMUsers(ctx, scimAuthn, SCIMFilter, PageRequest) iter.Seq2[PageEvent[SCIMUser], error]
UpsertSCIMGroup(ctx, scimAuthn, scimGroupID, SCIMGroupInput) (SCIMGroup, error)
DeleteSCIMGroup(ctx, scimAuthn, scimGroupID) error
SCIMGroup(ctx, scimAuthn, scimGroupID) (SCIMGroup, error)
SCIMGroups(ctx, scimAuthn, SCIMFilter, PageRequest) iter.Seq2[PageEvent[SCIMGroup], error]

CreateOAuthIssuer(ctx, authn, TrustedRequest, CreateOAuthIssuerInput) (OAuthIssuer, error)
UpdateOAuthIssuer(ctx, authn, TrustedRequest, issuerID, UpdateOAuthIssuerInput) (OAuthIssuer, error)
DisableOAuthIssuer(ctx, authn, TrustedRequest, issuerID) error
EnableOAuthIssuer(ctx, authn, TrustedRequest, issuerID) error
CreateOAuthProtectedResource(ctx, authn, workspaceID, CreateOAuthProtectedResourceInput) (OAuthProtectedResource, error)
DisableOAuthProtectedResource(ctx, authn, workspaceID, resourceID) error
EnableOAuthProtectedResource(ctx, authn, workspaceID, resourceID) error
PreRegisterOAuthClient(ctx, authn, TrustedRequest, issuerID, OAuthClientRegistrationInput) (IssuedOAuthClient, error)
DisableOAuthClient(ctx, authn, TrustedRequest, clientID) error
EnableOAuthClient(ctx, authn, TrustedRequest, clientID) error
RotateOAuthClientSecret(ctx, authn, TrustedRequest, clientID) (IssuedOAuthClient, error)
ReplaceOAuthClientJWKS(ctx, authn, TrustedRequest, clientID, jwks) error
CreateOAuthInitialAccessToken(ctx, authn, TrustedRequest, issuerID, CreateOAuthInitialAccessTokenInput) (IssuedOAuthInitialAccessToken, error)
RevokeOAuthInitialAccessToken(ctx, authn, TrustedRequest, tokenID) error
RegisterOAuthClient(ctx, issuer, initialAccessToken, OAuthClientRegistrationInput) (IssuedOAuthClient, error)
BeginOAuthAuthorization(ctx, authn, BeginOAuthAuthorizationInput) (OAuthConsent, error)
ValidateOAuthAuthorizationRedirect(ctx, issuerURL, clientID, redirectURI) error
CompleteOAuthAuthorization(ctx, authn, continuation, approved) (OAuthAuthorizationResult, error)
ExchangeOAuthAuthorizationCode(ctx, ExchangeOAuthAuthorizationCodeInput) (OAuthTokenResponse, error)
RefreshOAuthToken(ctx, RefreshOAuthTokenInput) (OAuthTokenResponse, error)
IssueOAuthClientCredentials(ctx, OAuthClientCredentialsInput) (OAuthTokenResponse, error)
RevokeOAuthToken(ctx, RevokeOAuthTokenInput) error
RevokeOAuthGrant(ctx, authn, grantID) error
OAuthIssuers(ctx, authn, PageRequest) iter.Seq2[PageEvent[OAuthIssuer], error]
OAuthProtectedResources(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[OAuthProtectedResource], error]
OAuthClients(ctx, authn, issuerID, PageRequest) iter.Seq2[PageEvent[OAuthClient], error]
OAuthGrants(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[OAuthGrant], error]
AuthenticateOAuthAccessToken(ctx, resourceURI, rawToken) (OAuthAuthentication, error)
OAuthUserInfo(ctx, issuerURL, rawAccessToken) (OIDCUserInfo, error)
OAuthAuthorizationServerMetadata(ctx, issuer) (OAuthAuthorizationServerMetadata, error)
OAuthProtectedResourceMetadata(ctx, resource) (OAuthProtectedResourceMetadata, error)
OAuthJWKS(ctx, issuer) ([]byte, error)

AuthorizeAdmin(ctx, authn, permission) error
RequireAdminMutation(authn, TrustedRequest) error
SetInstanceRole(ctx, authn, TrustedRequest, userID, instanceRole) error
RemoveInstanceRole(ctx, authn, TrustedRequest, userID) error

AuditEvents(ctx, authn, workspaceID, PageRequest) iter.Seq2[PageEvent[AuditEvent], error]
InstanceAuditEvents(ctx, authn, PageRequest) iter.Seq2[PageEvent[AuditEvent], error]
RecordAudit(ctx, authn, AuditInput) error
VerifyAuditChain(ctx, authn) (AuditChainReport, error)
VerifyAuditChainFrom(ctx, authn, AuditChainCheckpoint) (AuditChainReport, error)

AddTransactionHook(TransactionHook) Subscription
AddEventListener(EventListener) Subscription
```

`RecordAudit` does not allow callers to provide `ActorID`, `ID`, or `OccurredAt`.
Credbound derives these values so that a consuming service cannot impersonate
an actor or backdate an entry.

`BeginPasswordReset` and `BeginEmailAuthentication` perform the same
cryptographic work whether or not the address exists, and both succeed with a
decoy result (`Deliverable` false) when the address does not belong to an
eligible account, so the host's error path never distinguishes the two cases.
The host answers the end user identically, and sends the email — carrying the
returned token — only when `Deliverable` is true. Every issued email proof
(`IssuedPasswordReset`, `IssuedEmailAuthentication`, `IssuedEmailOTP`,
`IssuedEmailVerification`) carries the flag; an empty `Token` or `Code` is a
consequence of a decoy, not the signal itself. `AuthenticatePassword` treats an account
without a password credential exactly like a wrong password, and answers
`ErrInvalidCredentials` for a locked account too: `ErrLocked` only exists for
accounts that exist, so returning it from the unauthenticated entry point
would be an existence oracle the host could relay by accident. The lockout is
still audited with reason `locked` and surfaces through `UserLockedEvent` and
`AuthenticationFailureEvent`. Flows that run after a proof of possession
(`VerifyTOTP`, `CompleteEmailOTP`) keep reporting `ErrLocked`.

`BeginEmailOTP` issues an 8-digit single-use code bound to a sealed
continuation that the host keeps on its side of the exchange and passes back
to `CompleteEmailOTP` with the code the user typed. Ineligible addresses
receive a well-formed decoy continuation with `Deliverable` false. A wrong code
counts toward the account lockout exactly like a wrong password; completion
otherwise behaves like `CompleteEmailAuthentication` (AAL1, `MethodEmail`,
second-factor reporting).

`Config.PasswordPolicy` optionally vets candidate passwords beyond the
built-in length rules on every acceptance path (bootstrap, user creation,
change, reset, invitation registration); an error wrapping `ErrInvalidInput`
rejects the password and any other error aborts the operation. The intended
implementation checks a breached-password corpus (for example HIBP over
k-anonymity).

`AuthenticationEvent`, `AuthenticationFailureEvent`, and `UserLockedEvent`
carry the `RequestMetadata` supplied through `WithRequestMetadata`, so
listeners can throttle or alert by client address without re-reading the audit
log.
`CompletePasswordReset` atomically installs the password — the account's
first, for a passwordless member provisioned by SSO JIT or SCIM — revokes the
user's PATs and OAuth grants, and clears the lockout counter; host-owned
sessions must be terminated by the host alongside it (`SessionStore`-capable
stores revoke server-side sessions in the same transaction). `ChangePassword`
refuses a locked account with `ErrLocked` (the actor is authenticated, so no
existence oracle) and counts a wrong current password toward the account
lockout exactly like a failed sign-in. It
revokes the user's sessions in the transaction that installs the new password
but deliberately leaves PATs and OAuth grants alone: the actor proved
possession of the current password, so a routine change is not a compromise
response — hosts that want the full cascade pair it with
`RevokeUserCredentials`.

`Config.SSOAssurance` registers, per SSO provider configuration, an
`SSOAssurancePolicy` over the authentication context the provider asserts
(`SSOClaims.ACR` — the OIDC `acr` claim or SAML `AuthnContextClassRef` — and
`SSOClaims.AMR`). `FinishSSO` completes only when the policy is satisfied and
fails with `ErrStepUpRequired` otherwise, so the AAL2 an SSO sign-in produces
is verified against the IdP's own assertion instead of assumed. The bundled
`ssoadapter` and `samladapter` forward the asserted context.

Three `SSOProvider` implementations are bundled: `ssoadapter` (OIDC —
Google, Microsoft, or any compliant issuer), `samladapter` (SAML 2.0), and
`githubadapter` (GitHub's OAuth-without-OIDC flow). `githubadapter` asserts
no authentication context, so its sign-ins stay AAL1 and a step-up request
fails with its `ErrStepUpUnsupported` sentinel — pair GitHub sign-in with
TOTP or passkeys for AAL2.

`AuthorizePermission` is the canonical tenant authorization. For a scoped
authentication (a PAT), the permission itself — or the `*` wildcard — must
additionally appear among the scopes: scopes are the least privilege chosen at
creation, and the membership role never widens them back. The coarse
role-based `Authorize` accepts a scoped credential only with the `*` wildcard.
A PAT scope is validated at creation as either `*` or a workspace permission
string. Both entry points reject a TOTP-pending context
(`Authentication.SecondFactorRequired`) with `ErrStepUpRequired` in every
workspace: the first factor alone never authorizes anything, whether or not
the workspace requires MFA.

`RegenerateRecoveryCodes` replaces the actor's recovery codes with a fresh
single-display set under a fresh interactive AAL2 authentication; the previous
set stops working in the same transaction. `AdminResetSecondFactor` is the
total-loss recovery path: an instance administrator with users write and an
admin mutation atomically removes the target's TOTP factor with its recovery
codes and every passkey and revokes their server-side sessions, so the account
falls back to its first factor; the administrator can never target their own
account, and hosts should notify the affected user out of band through
`SecondFactorResetEvent`.

`WithRequestMetadata(ctx, RequestMetadata)` attaches the client network context
that every audit event recorded while serving the request will carry. The host
resolves the real client address from its trusted proxy configuration;
Credbound library calls never read transport headers.

`HTTPRequestMetadata(next, trustedProxies...)` is the net/http middleware that
performs that resolution explicitly: without trusted proxies it records the
transport peer and reads no header; when the peer belongs to a trusted prefix
it takes the rightmost `X-Forwarded-For` address outside every trusted prefix,
failing toward the peer address on malformed input.

`ComputeAuditHash(previous, event)` is the canonical chain hash used by the
bundled stores; auditors can recompute it over exported logs.
`VerifyAuditChain` recomputes the whole chain from the genesis;
`VerifyAuditChainFrom` verifies only the delta after an
`AuditChainCheckpoint` — the `HeadSequence` and `HeadHash` of an earlier
report, kept in the caller's own trusted record — so periodic verification
stays proportional to new events instead of the full history.

`TrustedRequest.Local` must be set only by a server adapter that has verified
that the network peer is loopback. It must never be copied from a request
parameter, header, or body. `TrustedRequestFromAddr(remoteAddr)` derives it
correctly from `http.Request.RemoteAddr`.

`Config.TOTP` and `Config.Passkeys` are optional; a manager built without one
reports `ErrNotSupported` from the corresponding enrollment, verification, and
ceremony operations, exactly like the optional SCIM and OAuth store
capabilities. Read and cleanup operations that only touch the store
(`TOTPStatus`, `Passkeys`, `DeletePasskey`) keep working so a host can inspect
and remove leftover factors. `Config.Store` and `Config.Passwords` remain
required.

`CollectPage(seq)` drains a paginated sequence into `([]T, PageEnd, error)`
for callers that want one page and a cursor; streaming callers range over the
sequence and forward each `PageEvent` themselves.

User-input validation failures (addresses, passwords, names, roles, PAT
inputs) return a `*ValidationError{Field, Rule, Message}` retrievable with
`errors.As`; every `ValidationError` also satisfies
`errors.Is(err, ErrInvalidInput)`. Protocol-level rejections may return a
plain `ErrInvalidInput`.

Operation naming convention: `Begin.../Finish...` frame a ceremony whose
opaque state round-trips through the caller (WebAuthn, SSO);
`Begin.../Complete...` frame a flow finished by presenting a token or code
(reset, magic link, email OTP, OAuth authorization); `Confirm...` proves
possession to activate a pending resource (email addition, TOTP enrollment,
workspace domains).

`SignUp` is enabled by `Config.SignUp`; without it the operation returns
`ErrNotSupported`. It requires a `SignupStore`-capable store. The result
carries the created user, workspace, and an `IssuedEmailVerification` whose
token the host delivers; `SignUpResult.ExistingAccount` is true — with zero
values elsewhere and no error — when the address already has an account, so
the host answers identically and may send an "already registered" notice
instead. With `Config.SignUp.AutoVerifyEmail` the primary address is verified
immediately and the result includes an AAL1 `Authentication`.

Sessions require a `SessionStore`-capable store; otherwise every session
operation returns `ErrNotSupported`. `CreateSession` snapshots the actor's
`Authentication` behind an opaque `cbs_`-prefixed token returned once.
`AuthenticateSession` re-validates expiry, revocation, and user disablement,
touches the session's last-seen timestamp, and returns the snapshot with its
`Session` record. Sessions are immutable snapshots: hosts mint a new session
after `VerifyTOTP` (or any AAL change) and revoke the previous one.
`CompletePasswordReset`, `DisableUser`, and `RevokeUserCredentials` revoke the
user's sessions in the same transaction when the store supports sessions.
`SignOut` revokes a single session by possession of its raw token — the
ordinary logout, deliberately requiring no step-up so an AAL1 deployment can
sign out immediately; it is idempotent on already-revoked sessions. Sessions
are global, not workspace-scoped: a SCIM deprovisioning suspends the
membership (denying tenant authorization) without ending them; directory
offboarding that must end sessions everywhere uses `DisableUser` or
`RevokeUserSessions`. Every successful `AuthenticateSession` performs one
write transaction (last-seen touch plus audit); high-traffic hosts may cache
the result per token for a short, bounded interval.

Workspace domains require a `DomainStore`-capable store. `CreateWorkspaceDomain`
returns a DNS challenge value; the host proves control of the domain (for
example a TXT record) before calling `ConfirmWorkspaceDomain`. Only confirmed
domains carry policy. A claim left unconfirmed past `Config.DomainClaimTTL`
(default 7 days) loses its globally unique name reservation to a new claim
from any workspace, so an unverified claim can never permanently deny the
domain's real owner; confirmed domains never expire. `WorkspaceDomainPolicyInput` selects the auto-join role,
the SSO provider configuration used for JIT provisioning, and the SSO
enforcement flag. When enforcement is on, `AuthenticatePassword`,
`BeginEmailAuthentication`, `BeginEmailOTP`, `BeginPasswordReset`, and
`BeginPasskeyAuthentication` reject addresses at exactly that domain with
`ErrSSORequired`, which reflects domain policy rather than account existence.
Matching is exact and ASCII: subdomains require their own registration, and a
Unicode-spelled domain falls outside the policy fail-safe. Non-interactive
PATs are exempt, like the workspace MFA policy. JIT provisioning inside
`FinishSSO` creates a passwordless account only when no user owns the
verified address (SSO-002 still forbids auto-linking existing accounts).

`Config.WorkspaceRoles` extends workspace roles only. Every custom role
implicitly inherits from `member`; its inheritance and additional permissions
are validated during construction. `admin` receives every registered workspace
permission. A definition named `member` or `admin` may add permissions without
removing their built-in guarantees. Instance roles remain limited to `root`,
`developer`, `support`, `marketing`, and `sales`.

`SCIMAuthentication` is a server capability obtained through `AuthenticateSCIM`.
It must never be constructed from fields freely supplied by a client. A
configuration or rotation returns the secret in `IssuedSCIMCredential.Token`
only once; the public value's `Digest` field is empty.

`UpdateSCIMConfiguration` immediately recomputes the roles of all memberships
managed by that configuration. The configuration change, recomputed memberships,
and audit record are atomic.

`Config.OAuth` enables the module. Its `Pepper` contains at least 32 bytes.
`MetadataFetcher` is required for dynamic CIMD policies, `OIDCSigner` for an
OIDC issuer, and `ClientAssertions` for `private_key_jwt`. Setting
`Config.OAuth` on a store that does not implement `OAuthStore` fails `New`
with `ErrInvalidInput` — explicit intent never degrades silently; without
`Config.OAuth` every OAuth operation returns `ErrNotSupported`.

`SignupStore`, `SessionStore`, `DomainStore`, and `PasskeyCredentialStore`
are optional store capabilities detected by type assertion exactly like
`SCIMStore` and `OAuthStore`. The bundled in-memory, SQLite, and PostgreSQL
stores implement all of them.

`BeginDiscoverablePasskeyAuthentication` starts a usernameless WebAuthn
ceremony: no address is asked and the challenge carries an empty
`allowCredentials` list, so no per-address answer exists to probe — closing
the residual enumeration signal of the email-first flow, whose per-address
decoy always fabricates exactly one credential while a real account may show
its count. `FinishDiscoverablePasskeyAuthentication` resolves the account
from the asserted credential (the provider verifies the asserted user handle
belongs to it), refuses disabled accounts and confirmed EnforceSSO domains —
the domain policy checked by address at Begin in the email-first flow is
enforced here against the resolved account's primary address — and consumes
the single-use ceremony like the email-first flow. Both require a provider
implementing `DiscoverablePasskeyProvider` (the bundled `webauthnadapter`
does) and a `PasskeyCredentialStore`-capable store; otherwise they return
`ErrNotSupported`. Session tokens are digested with the derived HMAC key under the
`session:` domain; session records never expose the token after creation.

`BeginOAuthAuthorization` validates the client, redirect URI, PKCE, resource,
scopes, and membership, then returns a sealed continuation for the host UI.
Only `CompleteOAuthAuthorization` can create the grant and code. Codes, tokens,
and secrets in results are returned only once and are never available through
persisted models.

## OAuth/MCP HTTP adapter

The optional `oauthhttp` package exposes composable handlers for discovery,
authorization, DCR, token issuance, revocation, UserInfo, JWKS, and bearer
validation. `HandlerConfig.Authenticate` supplies the existing host session and
`HandlerConfig.PresentConsent` transfers a validated `OAuthConsent` to the
host-service UI. Only `CompleteOAuthAuthorization` can turn that continuation
into an approval or denial.

`oauthhttp.NewMetadataFetcher` provides the CIMD network adapter with special
address blocking, no redirects, size and duration limits, and document
validation. `oauthclientadapter.NewJWTAssertionVerifier` validates ES256 or
RS256 `private_key_jwt` assertions, pins HTTPS JWKS resolution to validated
public addresses, caches bounded documents, and requires an atomic replay
store. The host service retains responsibility for TLS, sessions, CSRF,
distributed rate limiting, sign-in pages, and consent pages.

## SCIM HTTP adapter

The optional `scimhttp` package implements SCIM 2.0 without starting a server:

```go
handler, err := scimhttp.New(auth)
if err != nil {
    return err
}
router.Handle("/scim/v2/", http.StripPrefix("/scim/v2", handler))
```

The host service remains responsible for TLS, rate limiting, overall request
size, access logs, and commercial SCIM enablement. The adapter provides
`ServiceProviderConfig`, `ResourceTypes`, `Schemas`, `Users`, `Groups`, and
`.search`. It uses a SCIM bearer credential, opaque cursors, a maximum limit of
100, and `application/scim+json`.

Unknown SCIM profile attributes are retained on the tenant-scoped link. Only the
primary email created with a new user participates in the global identity model;
other SCIM email addresses remain profile attributes and do not become sign-in
identifiers. Without `TrustDirectoryEmails`, even the primary address remains
unverified and cannot be used to sign in.

## Transactional hooks

`TransactionHook` lets the host service add its own writes to the Credbound
transaction. The hook runs after the mutation and before the audit write:

```go
type TransactionHook interface {
    ApplyUserCreate(context.Context, Tx, UserCreateChange) error
    ApplyWorkspaceCreate(context.Context, Tx, WorkspaceCreateChange) error
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
    ApplySSOLink(context.Context, Tx, SSOLink) error
    ApplySSOUnlink(context.Context, Tx, SSOUnlink) error
    ApplyRoleGrant(context.Context, Tx, RoleGrant) error
    ApplyInstanceRoleChange(context.Context, Tx, InstanceRoleChange) error
    ApplyInstanceRoleRemoval(context.Context, Tx, InstanceRoleRemoval) error
    ApplyClientAudit(context.Context, Tx, ClientAuditRecord) error
    ApplyUserStatusChange(context.Context, Tx, UserStatusChange) error
    ApplyUserProfileChange(context.Context, Tx, UserProfileChange) error
    ApplyWorkspaceChange(context.Context, Tx, WorkspaceChange) error
    ApplyMembershipChange(context.Context, Tx, MembershipChange) error
    ApplyWorkspaceInvitationChange(context.Context, Tx, WorkspaceInvitationChange) error
    ApplyUserCredentialRevocation(context.Context, Tx, UserCredentialRevocation) error
    ApplySecondFactorReset(context.Context, Tx, SecondFactorReset) error
    ApplyUserAnonymization(context.Context, Tx, UserAnonymization) error
    ApplyRecoveryCodeRegeneration(context.Context, Tx, RecoveryCodeRegeneration) error
    ApplyOAuthChange(context.Context, Tx, OAuthChange) error
    ApplyWorkspaceDomainChange(context.Context, Tx, WorkspaceDomainChange) error
    ApplySessionCreation(context.Context, Tx, SessionCreation) error
    ApplySessionRevocation(context.Context, Tx, SessionRevocation) error
    ApplyUserSessionRevocation(context.Context, Tx, UserSessionRevocation) error
    ApplySCIMConfigurationCreate(context.Context, Tx, SCIMConfigurationChange) error
    ApplySCIMUserProvision(context.Context, Tx, SCIMUserChange) error
    ApplySCIMUserUpdate(context.Context, Tx, SCIMUserChange) error
    ApplySCIMUserDeprovision(context.Context, Tx, SCIMUserChange) error
    ApplySCIMGroupUpsert(context.Context, Tx, SCIMGroupChange) error
    ApplySCIMGroupDelete(context.Context, Tx, SCIMGroupChange) error
}
```

An implementation embeds `UnimplementedTransactionHook`. Hooks run sequentially
and must not perform external I/O, invoke another `Manager` mutation, retain the
`Tx`, or use it from another goroutine.

SQLite and PostgreSQL each expose `TxFrom(credbound.Tx) (*Tx, bool)` and
`(*Tx).SQL() *sql.Tx`. The handle becomes invalid when the callback ends.

`Bootstrap` calls `ApplyUserCreate` and then `ApplyWorkspaceCreate` within its
single transaction. The workspace hook is intended in particular for atomic
host-service credit or quota allocations.

## Events

`EventListener` observes committed facts. Its `On...` methods return errors for
observability only: the `Manager` never propagates them and they do not interrupt
other listeners. `AnyEventListener` is the catch-all companion: a listener that
also implements it receives every event through
`OnAnyEvent(ctx, name EventName, event any)` — invoked after its typed `On...`
method, with the same typed event struct — so whole-stream consumers (outbox
writers, webhook dispatchers) need one method instead of the full interface.

Events cover:

- bootstrap, self-service signup, and user and workspace creation;
- user profile updates (`user.profile_updated`);
- workspace lifecycle, memberships, and invitations;
- passwords and authentication (email OTP reuses the email-authentication
  and generic authentication events, distinguishable by their `Operation`);
- email addresses;
- TOTP, recovery codes, passkeys, and PATs;
- server-side sessions (created, revoked, user-wide revocation);
- SSO, including JIT provisioning;
- workspace domains (created, confirmed, policy updated, removed);
- RBAC and instance roles;
- SCIM configuration, users, and groups;
- OAuth clients, issuers, resources, CIMD, authorizations, and tokens;
- client-supplied audit and audit unavailability.

Each `EventMeta.ID` is a UUIDv7. The `Name` field contains a stable, unversioned
name such as `user.created` or `workspace.created`. Payloads follow the library
version. General events never carry secrets.

After the `Bootstrap` commit, the order is `user.created`, `workspace.created`,
then `bootstrap.completed`.

A direct Segment listener is best effort. Guaranteed delivery writes to a
host-owned outbox from the transactional hook; the event UUIDv7 serves as both
the idempotency key and `messageId`.

Lists emit a final `PageEnd` element through their page variant when a transport
needs to encode the following NDJSON contract:

```json
{"type":"item","data":{"id":"..."}}
{"type":"page_end","next_cursor":"opaque","has_more":true}
```

## Errors

Callers use `errors.Is` with the sentinel errors:

- `ErrInvalidCredentials`
- `ErrUnauthorized`
- `ErrForbidden`
- `ErrStepUpRequired`
- `ErrConflict`
- `ErrNotFound`
- `ErrNotSupported`
- `ErrInvalidInput`
- `ErrExpired`
- `ErrLocked`
- `ErrSSORequired`
- `ErrDomainVerification`
- `ErrAuditUnavailable`
- `ErrAuditCompromised`
- `ErrTransactionRejected`

Three further sentinels are contracts between a security provider and the
manager, not manager-to-host results: `ErrNoPasskey` (the passkey provider
reports the user has no passkey), `ErrPasskeyCloneDetected` (the passkey
provider rejects an assertion whose signature counter regressed; the caller
still receives `ErrInvalidCredentials`), and `githubadapter.ErrStepUpUnsupported`
(GitHub asserts no authentication context, so the adapter refuses step-up
ceremonies).

An application HTTP adapter must translate them to RFC 9457 with
`Content-Type: application/problem+json` and at least `type`, `title`, `status`,
and `detail`. The package-level `HTTPStatus(error) int` maps every sentinel to
its canonical status code (400, 401, 403, 404, 409, 422, 429, 501, 503; 500
for `ErrAuditCompromised` and anything unrecognized) so adapters share one
table instead of each maintaining an `errors.Is` ladder; the adapter still
owns the problem-document body. `scimhttp` is the
protocol-specific exception: it produces the SCIM error schema with
`Content-Type: application/scim+json`.
