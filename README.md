# Credbound

[![CI](https://github.com/deepteams/credbound/actions/workflows/ci.yml/badge.svg)](https://github.com/deepteams/credbound/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/deepteams/credbound.svg)](https://pkg.go.dev/github.com/deepteams/credbound)
[![Go Report Card](https://goreportcard.com/badge/github.com/deepteams/credbound)](https://goreportcard.com/report/github.com/deepteams/credbound)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Credbound is a Go authentication and authorization library, built at Deepteams
and open to everyone. It centralizes security invariants that would otherwise
be reimplemented in every project:

- local password authentication;
- WebAuthn passkeys;
- TOTP second factor and recovery codes;
- password reset, magic-link, and email OTP sign-in through single-use,
  expiring email proofs with enumeration-resistant initiation;
- an optional password policy port for breached-password (HIBP) vetting;
- built-in account lockout after consecutive password or TOTP failures;
- multiple verified email addresses per user, with one primary address, plus an
  updatable display name (self-service with a recent sign-in, any account by an
  instance administrator);
- transactional tracking of the latest authentication (`last_seen_at`);
- optional SSO per SaaS application (Google, GitHub, Microsoft, OIDC, and SAML);
- freshness checks for step-up operations;
- Personal Access Tokens (PATs) displayed only once;
- workspace isolation and extensible RBAC (`admin`, `member`, and application roles);
- workspace invitations whose invitee chooses their own password, and an
  optional per-workspace MFA requirement;
- optional self-service signup that atomically creates the user, their
  workspace, and their admin membership, with enumeration-resistant handling
  of already-registered addresses;
- optional server-side sessions behind single-display `cbs_` tokens, with
  device listings and a session-revocation cascade on reset, disable, and
  credential revocation;
- optional verified workspace email domains (DNS-challenge capture) with
  per-domain SSO enforcement and just-in-time provisioning of passwordless
  members from a trusted SSO provider;
- atomic revocation of every PAT and OAuth grant of a user;
- optional SCIM 2.0 provisioning per workspace (`Users`, `Groups`, `.search`);
- optional OAuth 2.0/OIDC authorization-server capabilities for remote MCP
  resources, with pre-registration, independent CIMD and DCR policies, PKCE,
  opaque rotating tokens, pairwise subjects, and revocation cascades;
- instance administration (`root`, `developer`, `support`, `marketing`, `sales`);
- an append-only, hash-chained audit log — carrying the client IP address and
  user agent supplied by the host — that the host service can extend without
  spoofing the actor or timestamp, and whose integrity `VerifyAuditChain`
  recomputes end to end;
- transactional hooks for atomic host-service business writes;
- typed post-commit events for analytics, notifications, and external
  integrations;
- structured logs, traces, and OpenTelemetry metrics.

The project follows a _Specs First_ approach. The product contract is defined in
[`specs/PRD.md`](specs/PRD.md), and the Go API in [`specs/API.md`](specs/API.md).

## Status

The core, in-memory store, SQLite store, PostgreSQL store and migrations, and
security adapters are implemented. Version `v0` may still introduce breaking
changes before the first stable release. CI applies the PostgreSQL migrations
into the dedicated `credbound` schema and exercises lifecycle, OAuth, pagination, transactional
hooks, and append-only audit behavior against a real PostgreSQL service.

## Security principles

- No password, TOTP secret, PAT, or recovery code is stored in plaintext.
- A raw PAT is returned only when it is created.
- Sensitive mutations and their audit records are atomic at repository level.
- A secondary address cannot authenticate until its time-limited proof has been
  verified.
- An SSO identity is explicitly linked by `issuer` and `subject`; the IdP email
  address never triggers an automatic account merge.
- A PAT can never satisfy an interactive step-up request.
- Completing a password reset atomically revokes the account's PATs and OAuth
  grants and clears its lockout; a locked account still performs the same
  password derivation and answers with the same public error as a wrong
  password, so it never confirms whether an address exists.
- Every audit event is hash-chained to its predecessor inside the commit
  transaction; tampering is detectable with `VerifyAuditChain`.
- Access to application resources must always provide a `workspace_id`.
- All entity IDs created by Credbound are canonical UUIDv7 values that are
  monotonic within the process.

## Integration

Credbound is a library, not a server. The host service remains responsible for
cookies, CSRF, rate limiting, its TLS/H2/H3 reverse proxy, and its UI. WebAuthn
ceremonies remain transport-agnostic: the JSON produced by the library is sent
to the browser, whose response is then passed back to the library.

### Sessions and the `Authentication` capability

Every successful sign-in (`AuthenticatePassword`, `CompleteEmailAuthentication`,
`CompleteEmailOTP`, `FinishPasskeyAuthentication`, `FinishSSO`, `VerifyTOTP`)
returns an `Authentication` value. It is a **security capability, not a lookup
result**: `Level`, `Method`, and `AuthenticatedAt` directly drive step-up
checks and per-workspace MFA enforcement. The host owns sessions and must:

- store the `Authentication` server-side (or in a tamper-proof, signed and
  encrypted cookie) and reconstruct it verbatim on each request;
- never rebuild one from client-supplied fields and never upgrade `Level`
  itself — only `VerifyTOTP`, a passkey, or SSO reauthentication may
  produce AAL2;
- treat `SecondFactorRequired: true` as a *pending* session: keep it out of
  authorized paths, send the user to `VerifyTOTP`, and store the AAL2
  `Authentication` that it returns;
- terminate its own sessions for a user when `CompletePasswordReset`,
  `DisableUser`, or `RevokeUserCredentials` fires — the library revokes PATs
  and OAuth grants but cannot see host sessions.

`RequireStepUp` accepts only interactive AAL2 authentications newer than
`Config.StepUpMaxAge`; a PAT can never satisfy it.

Hosts that would rather not manage session persistence themselves can use the
optional server-side session module (`CreateSession`, `AuthenticateSession`,
`Sessions`, `RevokeSession`, `RevokeUserSessions`), available when the store
implements `SessionStore` — the bundled in-memory, SQLite, and PostgreSQL
stores all do. It persists the `Authentication` snapshot behind a
single-display `cbs_` token (digest-only at rest, absolute
`Config.SessionTTL` expiry), lists a user's devices, and extends the
revocation cascade of `CompletePasswordReset`, `DisableUser`, and
`RevokeUserCredentials` to those sessions within the same transaction. The
token's transport — cookies, CSRF, TLS — remains host-owned.

### Minimal setup

```go
store, err := sqlite.New(database)
if err != nil {
    return err
}

passkeys, err := webauthnadapter.New(webauthnadapter.Config{
    RPID:          "app.example.com",
    RPDisplayName: "My application",
    RPOrigins:     []string{"https://app.example.com"},
    UserHandleKey: userHandleKey,
})
if err != nil {
    return err
}

passwords, err := password.New(password.DefaultParams())
if err != nil {
    return err
}

totpProvider, err := totpadapter.New(totpadapter.Config{Issuer: "My application"})
if err != nil {
    return err
}

auth, err := credbound.New(credbound.Config{
    Store:          store,
    Passwords:      passwords,
    TOTP:           totpProvider,  // optional second factor
    Passkeys:       passkeys,      // optional second factor
    SecretKey:      encryptionKey, // exactly 32 bytes
    PATPepper:      patPepper,     // at least 32 bytes
    RecoveryPepper: recoveryPepper,// at least 32 bytes
    EmailVerificationTTL: 24 * time.Hour,
    SSOProviders: []credbound.SSOProvider{
        googleProvider,
        oidcProvider,
    },
    WorkspaceRoles: []credbound.RoleDefinition{
        {Role: "viewer", Permissions: []credbound.WorkspacePermission{"documents.read"}},
        {Role: "editor", Permissions: []credbound.WorkspacePermission{"documents.write"}, Inherits: []credbound.Role{"viewer"}},
    },
    TransactionHooks: []credbound.TransactionHook{billingHook},
    EventListeners:   []credbound.EventListener{segmentListener},
})
```

The snippet assumes the embedded migrations have already been applied to
`database` (see `migrations.SQLite()` and `migrations.PostgreSQL()` below).
Only `Store`, `Passwords`, and the three secrets are required: the `TOTP` and
`Passkeys` providers are optional, and their flows return `ErrNotSupported`
until the host wires them. A complete, runnable integration — SQLite,
migration application, first-run bootstrap, and a cookie-session HTTP layer
following the sessions contract above — lives in
[`examples/minimal`](examples/minimal/main.go).

Each SSO provider has a UUIDv7 configuration identifier. The host service
implements the `SSOProvider` port for the IdPs it enables and remains responsible
for network exchanges, client secrets, and cryptographic callback validation.
Credbound handles sealed continuations, explicit linking, AAL2, step-up with
forced IdP reauthentication, persistence, and auditing.

The `admin` and `member` roles are always available. The workspace role catalog
is frozen when the `Manager` is constructed; application roles may inherit from
one another, and the application may add permissions to `admin` or `member`
without removing their built-in guarantees. Access is authorized by permission
through `AuthorizePermission`. This extension never adds instance-administration
roles or permissions.

### Optional SCIM provisioning

The in-memory, SQLite, and PostgreSQL stores implement `SCIMStore`. A SaaS
application offering SCIM creates a workspace configuration, returns the raw
credential to the directory once, and then mounts the adapter:

```go
scim, err := scimhttp.New(auth)
if err != nil {
    return err
}
router.Handle("/scim/v2/", http.StripPrefix("/scim/v2", scim))
```

The SaaS application retains the commercial decision to enable SCIM. Credbound
manages the service credential, configuration isolation, passwordless users,
groups, mappings to registered roles, membership suspension, auditing, and
events. Deprovisioning never disables the global user account.

### Optional OAuth, OIDC, and MCP authorization

`Config.OAuth` enables the authorization-server module. The host creates an
issuer and workspace-bound protected resource, then selects pre-registration,
CIMD, and DCR policies independently. The optional `oauthhttp.Handler` exposes
discovery, authorization, token, revocation, registration, UserInfo, and JWKS
routes when mounted by the host. `oauthhttp.Protect` validates a bearer token
again at the resource boundary before calling an MCP handler.

Use `oauthclientadapter.JWTAssertionVerifier` for hardened `private_key_jwt`
verification and `oauthhttp.MetadataFetcher` for CIMD loading. The latter
blocks special/private destinations, redirects, oversized documents, and
unbounded concurrency. `oidcadapter.NewES256KeyRing` publishes one active
signing key and any verification-only retiring keys during rotation.

The adapter contract is summarized in
[`specs/oauthhttp.openapi.yaml`](specs/oauthhttp.openapi.yaml). The host still
owns login and consent UI, sessions, CSRF, rate limits, TLS, and route-level
commercial policy.

A `TransactionHook` extends the Credbound transaction before its audit record
and commit. This is the intended extension point for atomically creating a
freemium credit ledger, quota, or outbox row in the host-service database.
SQLite and PostgreSQL provide a typed `TxFrom`; the handle is valid only during
the callback. Any hook error or panic cancels the entire mutation.

An `EventListener` then receives the committed fact, such as `user.created` or
`workspace.created`. It may call Segment on a best-effort basis. Its error is
observed but never returned to the caller, and it does not prevent subsequent
listeners from running. For guaranteed delivery, the hook writes to a
transactional outbox and a host-service worker dispatches it after commit.

The two interfaces embed `UnimplementedTransactionHook` and
`UnimplementedEventListener`, respectively, so that an integration only needs
to implement useful callbacks. Their full contract and payload list are defined
in [`specs/API.md`](specs/API.md); the architecture decision is documented in
[`ADR-008`](specs/adr/ADR-008-transaction-hooks-and-events.md).

To add a business fact to the audit log, the service calls `RecordAudit` with an
`AuditInput`. Credbound always constructs the UUIDv7 identifier, actor, and
timestamp.

Embedded Goose migrations are available through `migrations.SQLite()` and
`migrations.PostgreSQL()`. Versions are timestamps so they interleave with the
host service's own migrations, and on PostgreSQL every table lives in the
dedicated `credbound` schema. Hosts without a migration tool call
`migrations.ApplySQLite(ctx, db)` or `migrations.ApplyPostgreSQL(ctx, db)`
instead — idempotent, one transaction per migration; pick goose or the
helpers for a given database, never both. The first `Bootstrap` call atomically creates the
first user, their workspace, their `admin` membership, and their instance-level
`root` role.

Operational guidance is in [`specs/OPERATIONS.md`](specs/OPERATIONS.md), the
release process in [`specs/RELEASING.md`](specs/RELEASING.md), and vulnerability
reporting in [`SECURITY.md`](SECURITY.md).

### Testing your integration

The [`credboundtest`](credboundtest) package builds a fully wired `Manager` for
host-service tests: in-memory store, fast fake password hasher, deterministic
clock and randomness, and TOTP/passkey fakes whose ceremonies succeed with
fixed inputs. Nothing in it is safe for production.

```go
func TestSignIn(t *testing.T) {
    clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
    manager := credboundtest.NewManager(t, credboundtest.WithClock(clock))
    authn, workspace := credboundtest.Bootstrap(t, manager)

    issued, err := manager.CreatePAT(context.Background(),
        credboundtest.AAL2(authn.UserID, clock.Now()), // test-only step-up
        credbound.CreatePATInput{Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"}})
    if err != nil {
        t.Fatal(err)
    }
    _ = issued.Token // raw token, returned exactly once
}
```

## Verification

```sh
make test
make coverage
make verify
```

`make coverage` enforces consolidated coverage strictly above 90% for maintained
code. Generated sqlc code and the generated PostgreSQL store are excluded from
this measurement; their reproducibility is checked by `make generate`.

## Contributing

Credbound is specs-first: behavior changes update
[`specs/PRD.md`](specs/PRD.md) and [`specs/API.md`](specs/API.md) alongside the
code, and `make verify` must pass. See [CONTRIBUTING.md](CONTRIBUTING.md) and
the [code of conduct](CODE_OF_CONDUCT.md). Vulnerabilities are reported
privately per [SECURITY.md](SECURITY.md), never through public issues.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
