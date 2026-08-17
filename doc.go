// Package credbound provides transport-independent authentication,
// workspace authorization and instance-administration primitives for Go
// SaaS services: local accounts, TOTP and passkey factors, magic links,
// email OTP, password reset, PATs, SSO linking, workspace RBAC, invitations,
// SCIM provisioning, an OAuth 2.1/OIDC authorization server for MCP
// resources, and a hash-chained audit log.
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
// ErrLocked, ErrAuditUnavailable, ErrAuditCompromised and
// ErrTransactionRejected. User-input validation failures additionally carry
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
// verification and ceremony operations. SCIM provisioning requires the
// store to implement SCIMStore, and the OAuth server requires both
// Config.OAuth and a store implementing OAuthStore; absent capabilities
// likewise report ErrNotSupported without affecting anything else.
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
