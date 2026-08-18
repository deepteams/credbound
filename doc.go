// Package credbound provides transport-independent authentication,
// workspace authorization and instance-administration primitives for Go
// SaaS services: local accounts, self-service signup, TOTP and passkey
// factors, magic links, email OTP, password reset, PATs, server-side
// sessions, SSO linking with verified workspace domains and JIT
// provisioning, workspace RBAC, invitations, SCIM provisioning, an OAuth
// 2.1/OIDC authorization server for MCP resources, and a hash-chained
// audit log.
//
// Credbound starts no HTTP server and issues no cookies or JWTs. The host
// service owns TLS, sessions, CSRF, throttling and UI; the optional oauthhttp
// and scimhttp packages provide mountable protocol handlers. The full
// contract lives in specs/API.md and specs/PRD.md in the module source.
//
// # Construction
//
// A Manager is built once from a validated Config:
//
//	auth, err := credbound.New(credbound.Config{
//		Store:          store,     // required persistence port
//		Passwords:      passwords, // required Argon2id-style hasher
//		SecretKey:      key,       // exactly 32 bytes
//		PATPepper:      patPepper, // at least 32 bytes
//		RecoveryPepper: recPepper, // at least 32 bytes
//	})
//
// New rejects every invalid configuration invariant; cryptographic values
// have no weak fallback. Zero durations and limits fall back to safe
// defaults (10 minute step-up window, 12 character minimum password, 10
// failed logins before a 15 minute lockout, and so on).
//
// # API map
//
// The Manager exposes every operation as a flat method set; this map groups
// the entry points by domain so the one you need is a search away:
//
//   - Sign-in: AuthenticatePassword, VerifyTOTP, Begin/FinishPasskeyAuthentication,
//     Begin/CompleteEmailAuthentication (magic link), Begin/CompleteEmailOTP,
//     Begin/FinishSSO, AuthenticatePAT, SignUp.
//   - Passwords: ChangePassword, Begin/CompletePasswordReset.
//   - Second factor: Begin/ConfirmTOTPEnrollment, DisableTOTP,
//     RegenerateRecoveryCodes, TOTPStatus; Begin/FinishPasskeyRegistration,
//     DeletePasskey, Passkeys; AdminResetSecondFactor for total loss.
//   - Email addresses: BeginEmailAddition, ConfirmEmail,
//     ResendEmailVerification, SetPrimaryEmail, RemoveEmail, Emails.
//   - Server-side sessions: CreateSession, AuthenticateSession, SignOut,
//     Sessions, RevokeSession, RevokeUserSessions.
//   - SSO linking and domains: BeginSSOLink, BeginSSOStepUp, UnlinkSSO,
//     SSOIdentities; CreateWorkspaceDomain, ConfirmWorkspaceDomain,
//     UpdateWorkspaceDomainPolicy, RemoveWorkspaceDomain, WorkspaceDomains.
//   - PATs and revocation: CreatePAT, RevokePAT, PATs; RevokeUserCredentials.
//   - Tenant authorization: AuthorizePermission (canonical), Authorize,
//     GrantRole, RequireStepUp.
//   - Lifecycle: Bootstrap, CreateUser, UpdateUser, Disable/EnableUser,
//     CreateWorkspace, UpdateWorkspace, Disable/EnableWorkspace,
//     AddMembership, SetMembershipStatus, RemoveMembership, the User,
//     Workspace, Membership getters, and the Users, Workspaces,
//     UserWorkspaces, Memberships listings.
//   - Invitations: InviteToWorkspace, AcceptInvitation,
//     RegisterFromInvitation, RevokeInvitation, WorkspaceInvitations.
//   - Privacy (data-subject requests): ExportUserData, AnonymizeUser.
//   - Instance administration: AuthorizeAdmin, RequireAdminMutation,
//     SetInstanceRole, RemoveInstanceRole, and the Admin* variants of user,
//     workspace and profile mutations.
//   - SCIM provisioning: CreateSCIMConfiguration and the SCIM* resource
//     operations (see scim.go).
//   - OAuth 2.1/OIDC server: the OAuth* operations (see oauth.go and the
//     mountable oauthhttp package).
//   - Audit and extension: RecordAudit, AuditEvents, InstanceAuditEvents,
//     VerifyAuditChain, VerifyAuditChainFrom, AddTransactionHook,
//     AddEventListener.
//
// # Naming
//
// Multi-step flows follow one convention: Begin.../Finish... frame a
// ceremony whose opaque state round-trips through the caller (WebAuthn,
// SSO); Begin.../Complete... frame a flow finished by presenting a token or
// code (reset, magic link, email OTP, OAuth authorization); Confirm...
// proves possession to activate a pending resource (email addition, TOTP
// enrollment, workspace domains).
//
// Operations exist at up to three privilege scopes, and the signature tells
// them apart: self-service methods take only the actor; workspace-scoped
// mutations authorize through workspace RBAC (AuthorizePermission); and
// instance-scoped administrative mutations — the Admin* methods plus
// Disable/EnableUser, SetInstanceRole, RemoveInstanceRole,
// RevokeUserSessions and RevokeUserCredentials on another account — take a
// TrustedRequest and demand an admin mutation (a fresh AAL2 step-up, or a
// TrustedRequest verified as loopback by the server adapter).
//
// # Authentication and sessions
//
// Authentication is a server-side capability describing who authenticated,
// how (Method), at what assurance level (AAL1 or AAL2) and when. It is
// returned by AuthenticatePassword, VerifyTOTP, FinishPasskeyAuthentication,
// FinishSSO, CompleteEmailAuthentication, CompleteEmailOTP and
// AuthenticatePAT. The host stores it in its own session and passes it back
// as the actor of later calls; it must never be rebuilt from fields supplied
// by a client, because every authorization decision trusts it.
//
// A password or email login yields AAL1 and reports through
// SecondFactorRequired whether an active TOTP factor still has to be
// verified; VerifyTOTP upgrades the context to AAL2. Passkey and SSO
// authentication produce AAL2 directly. Sensitive operations demand a fresh
// interactive AAL2 context (RequireStepUp) and fail with ErrStepUpRequired
// otherwise. Administrative mutations use RequireAdminMutation, which may
// waive the step-up only for a TrustedRequest built from an actually
// observed loopback peer (see TrustedRequestFromAddr) — never from
// client-supplied headers.
//
// # Pagination
//
// List operations return iter.Seq2[PageEvent[T], error] with opaque cursors
// and a default limit of 50. Each page streams item events followed by a
// final page_end event, matching the NDJSON transport contract:
//
//	{"type":"item","data":{"id":"..."}}
//	{"type":"page_end","next_cursor":"opaque","has_more":true}
//
// CollectPage drains one page into ([]T, PageEnd, error) for callers that
// want a slice and a cursor; streaming callers range over the sequence and
// forward each PageEvent.
//
// # Errors
//
// Failures map to sentinel errors compared with errors.Is:
// ErrInvalidCredentials, ErrUnauthorized, ErrForbidden, ErrStepUpRequired,
// ErrConflict, ErrNotFound, ErrNotSupported, ErrInvalidInput, ErrExpired,
// ErrLocked, ErrSSORequired, ErrDomainVerification, ErrAuditUnavailable,
// ErrAuditCompromised and ErrTransactionRejected. Two more are contracts
// between a security provider and the manager rather than manager-to-host
// results: ErrNoPasskey (a passkey provider reporting the user has none) and
// ErrPasskeyCloneDetected (a passkey provider rejecting a cloned authenticator;
// the caller still sees ErrInvalidCredentials). User-input validation failures additionally carry
// a *ValidationError{Field, Rule, Message} retrievable with errors.As; every
// ValidationError also satisfies errors.Is(err, ErrInvalidInput). Public
// errors never contain secrets, and enumeration-sensitive flows
// (AuthenticatePassword, BeginPasswordReset, BeginEmailAuthentication,
// BeginEmailOTP) answer identically whether or not the account exists.
//
// # Extension points
//
// TransactionHook lets the host append its own writes to a Credbound
// mutation: hooks run inside the store transaction, after the mutation and
// before the audit write, so a hook error aborts the whole commit
// (ErrTransactionRejected). EventListener observes committed facts;
// listener errors are recorded for observability and never propagate.
// Both are registered in Config or later with AddTransactionHook and
// AddEventListener, and implementations embed UnimplementedTransactionHook
// or UnimplementedEventListener to stay compatible. PasswordPolicy vets
// candidate passwords beyond the built-in length rules (for example against
// a breached-password corpus), and SSOProvider injects the network adapter
// for each registered identity provider.
//
// # Optional capabilities
//
// Config.TOTP and Config.Passkeys are optional providers; a Manager built
// without one reports ErrNotSupported from the corresponding enrollment,
// verification and ceremony operations. Store capabilities are detected by
// type assertion: SCIM provisioning requires SCIMStore, the OAuth server
// requires Config.OAuth plus OAuthStore, self-service signup requires
// Config.SignUp plus SignupStore, server-side sessions (CreateSession,
// AuthenticateSession, SignOut, device listing and the revocation cascade)
// require SessionStore, and verified workspace domains with JIT provisioning
// and domain-enforced SSO require DomainStore. Absent capabilities report
// ErrNotSupported without affecting anything else; the bundled memory,
// SQLite and PostgreSQL stores implement all of them.
//
// # Audit
//
// Sensitive mutations and their audit events are committed atomically by the
// Store contract and fail closed when the audit cannot be persisted
// (ErrAuditUnavailable). Every audit event is hash-chained to its
// predecessor with ComputeAuditHash; VerifyAuditChain recomputes the chain
// and reports tampering as ErrAuditCompromised. WithRequestMetadata attaches
// the sanitized client IP address and user agent that audit events record.
package credbound
