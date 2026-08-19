# Changelog

All notable changes to Credbound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). While the module is `v0`,
breaking changes may land in any release and are called out explicitly.

## Unreleased

### Added

- `credboundtest.DiscoverablePasskeys` extends the passkey fake with
  usernameless sign-in over discoverable credentials, so a host can test
  `BeginDiscoverablePasskeyAuthentication` and
  `FinishDiscoverablePasskeyAuthentication` without a real authenticator.
  The plain `Passkeys` fake keeps returning `ErrNotSupported` for those
  flows, mirroring a provider that does not implement the optional port.

- `Config.SessionTouchInterval` coarsens the write every successful
  `AuthenticateSession` used to perform (last-seen touch plus audit event)
  to at most one write per session per interval, without giving up instant
  revocation: every store-backed check still runs on every call. The
  explicit trade-offs — last-seen granularity and audit density — replace
  each host inventing its own result cache, whose window delays
  revocation.

- The reads an administration interface needs no longer require
  over-granting or going without: `Manager.WorkspaceMembers` streams a
  workspace's memberships joined with each member's display name and
  primary email under workspace users read alone; the unused
  `admin.instance_roles.read` permission now has readers
  (`Manager.InstanceAdministrator`, `Manager.InstanceAdministrators`);
  `Manager.SCIMConfigurations` and `Manager.SCIMCredentials` inventory a
  workspace's provisioning domains and their credentials (digests
  omitted); and `Manager.OAuthInitialAccessTokens` inventories an issuer's
  DCR bootstrap credentials (digests omitted). Breaking for custom stores:
  the `Store`, `SCIMStore` and `OAuthStore` ports gain
  `InstanceAdministrators`, `SCIMConfigurations`/`SCIMCredentials` and
  `OAuthInitialAccessTokens` respectively; stores embedding the bundled
  implementations inherit them.

- `ExportUserData` now includes the tenant-scoped SCIM profiles, the
  workspace invitations the user accepted, and the user's OAuth grants,
  backed by the new optional `PrivacyStore` capability (implemented by
  every first-party store); `AnonymizeUser` scrubs SCIM profiles and
  accepted-invitation addresses in the same transaction.

- `Config.PATPrefix` sets the marker a PAT carries ahead of its indexed
  prefix and secret, replacing the hardcoded `cbp`; zero keeps `cbp`, and
  one to sixteen lowercase letters or digits are accepted (no underscore,
  the separator the parser splits on). Several deployments issuing PATs can
  now be told apart from a token's text alone — which is what a per-service
  check or a secret-scanning rule needs. Pick it before the first PAT is
  issued: the digest covers the whole token, marker included, and only the
  digest is stored, so a later change leaves every outstanding PAT
  unauthenticatable. SCIM credentials, sessions and OAuth tokens keep their
  own markers.

### Changed

- **Breaking: identifiers are `credbound.UUID`, not `string`.** Every identifier
  in the API — `User.ID`, `Authentication.UserID`, the `Store` port's
  parameters, the SSO provider's `ConfigurationID()` — is now the sixteen raw
  bytes PostgreSQL stores, comparable with `==` and usable as a map key. Text
  crosses the boundary through `ParseUUID` and `String()`, which is where a
  malformed identifier is now rejected: it can no longer travel through the
  library as a plain string. `credbound.UUID` is an alias for the package
  accepted into the Go standard library (golang/go#62026), vendored under
  `internal/uuid` until it ships.

  Two representations are deliberately unchanged, because they live outside the
  process and would otherwise invalidate what is already stored: the audit
  chain still hashes identifiers as canonical text, so existing chains stay
  verifiable, and the WebAuthn user handle is still derived from that same
  text, so registered passkeys keep resolving.

  Migrating a host means parsing at its own edges — `credbound.ParseUUID` on
  the way in, `String()` on the way out — and letting the compiler find the
  rest.

- **Breaking: `OAuthChange.ClientID` is now `ClientRecordID UUID`.** The field
  always carried Credbound's client record, like the `IssuerID`, `GrantID` and
  `ResourceID` beside it, but its name announced the protocol `client_id` — a
  different value, which is text and is a Client Identifier URL for CIMD
  clients. Hooks and listeners reading it get the record identifier under a
  name that says so; the protocol `client_id` is not carried by this payload
  and is read from the client record when needed.

### Removed

- **Breaking: SQLite is no longer supported.** The `sqlstore/sqlite` package,
  the embedded SQLite migrations (`migrations.SQLite`, `migrations.ApplySQLite`),
  the `credbound.StoreSQLite` store kind and the `modernc.org/sqlite`
  dependency are all gone. PostgreSQL is now the only SQL engine, which lets
  its store use the dialect natively — typed `uuid` parameters, `jsonb`
  operators, row-level locking and index-friendly predicates — instead of the
  portable subset the two engines had to share. Hosts that used SQLite for
  local development or tests should use the in-memory store (`memory.New`,
  which `credboundtest` already defaults to) or run PostgreSQL; hosts that
  used it in production must migrate their data to PostgreSQL before
  upgrading, as no automated path is provided.

### Fixed

- `max_age` values large enough to overflow a `time.Duration` — anything
  past roughly 292 years — wrapped to a negative duration that
  `BeginOAuthAuthorization` reads as "no freshness constraint at all",
  silently dropping the re-authentication an OIDC client asked for. The
  authorization endpoint now answers `invalid_request` instead.

- `memory.Store.AnonymizeUser` left the original address on the user
  record: it tombstoned the address rows but not the `User.Email`
  projection the SQL stores rebuild from their primary-address join, so a
  read after anonymization still returned the personal data on that store.

- `parseOAuthBearer` returned the token prefix alongside a false
  acceptance, unlike every sibling parser; a caller reading the identifier
  before the boolean was handed attacker-controlled input.

- SCIM list responses are now assembled in memory (the page is bounded at
  100 resources) before the status line is written, so a store read or
  serialization failure mid-page answers with a real SCIM error document
  instead of truncated JSON under a 200 the provisioning client would
  trust.

### Security

- The anonymous email-issuance throttle can no longer be used to grow
  storage without bound. The manager now keys `ClaimEmailIssuance` with a
  fixed-size HMAC of the normalized address — hostile input of any length
  costs one bounded, opaque row and a store dump reveals nothing about the
  addresses tried — and the bundled stores prune entries older than the
  cooldown on every claim, so the bookkeeping tracks the current window
  instead of accumulating every address ever submitted.

- The token and revocation endpoints now hold clients to their registered
  `token_endpoint_auth_method`. A client registered `client_secret_basic`
  is refused a correct secret delivered as a `client_secret` form field
  (`client_secret_post`, which neither registration nor the discovery
  document offers — RFC 6749 §2.3.1 discourages the body transport), and a
  request presenting Basic and a form secret at once uses two
  authentication methods (forbidden by RFC 6749 §2.3) and is refused
  outright. Breaking: the token-endpoint inputs gain `ClientSecretInBody`,
  which hosts with their own transport must set when the secret arrived in
  the body.

- A password sign-in can no longer complete after its password was
  concurrently replaced. `AuthenticatePassword` finalizes through the new
  `Store.RecordPasswordAuthentication`, which re-checks inside the
  finalization transaction that the verified hash is still the stored
  credential (a concurrent transparent rehash of the same password is
  retried, not refused), and password-derived `Authentication` values now
  carry a `CredentialDigest` fingerprint that `SessionStore.CreateSession`
  (breaking: new `credentialDigest` parameter) re-validates inside the
  session transaction — so a sign-in racing `ChangePassword` or
  `CompletePasswordReset` can neither finish nor mint a session that the
  replacement's revocation sweep should have killed. After a change the
  host re-authenticates with the new password before creating the
  follow-up session.

- `githubadapter` now runs PKCE (S256) end to end: `Begin` sends a
  `code_challenge` and seals the verifier into the ceremony continuation,
  and the code exchange presents `code_verifier`. GitHub recommends PKCE
  for OAuth apps since July 2025; a continuation sealed by a pre-PKCE
  `Begin` still completes without one.

- `Authorize` and `AuthorizePermission` now reject a TOTP-pending context
  (`Authentication.SecondFactorRequired`) with `ErrStepUpRequired` in every
  workspace, so a first factor alone never authorizes workspace operations
  even where `RequireMFA` is off. Deferring the pending context was
  previously a host-side contract only.
- A wrong current password in `ChangePassword` now counts toward the
  account lockout exactly like a failed sign-in, and a locked account is
  refused with `ErrLocked` before any verification, so a hijacked session
  can no longer brute-force the knowledge factor online.
- `SignUp` now marks its real verification issuance `Deliverable`, matching
  the issued-email-proof contract every other flow follows; a host honoring
  the send-only-when-`Deliverable` rule previously never delivered the
  signup verification email, leaving the account unable to authenticate.

- WebAuthn ceremonies are single use: passkey continuations now seal a
  ceremony id that the success commit consumes, so a captured
  `(continuation, response)` pair can never be replayed — signature
  counters alone cannot guarantee this, since many authenticators
  legitimately report a constant zero.
- Bearer validation and UserInfo now re-check `client.DisabledAt` on the
  shared grant-validation path. The bundled stores already revoked a
  disabled client's grants and tokens in the disable transaction; the
  re-check makes the kill switch hold for custom stores without that
  cascade. A disabled client can no longer drive a consent ceremony either,
  and only clients registered for `authorization_code` may begin one.
- Replaying an authentic, already-redeemed authorization code now revokes
  the grant and every access and refresh token derived from it (RFC 9700's
  reuse-detection response), emitting the new
  `oauth.authorization_code.reuse_detected` event; a replayed code
  previously failed alone while the first redeemer's tokens survived.
- `RevokeOAuthRefreshFamily` (refresh reuse detection and RFC 7009 refresh
  revocation) now also revokes the access tokens of the grants the family
  descends from, so a thief's already-minted access token dies with the
  family instead of surviving until expiry.
- **Breaking:** unconfirmed workspace-domain claims expire. A pending claim
  left unconfirmed past the new `Config.DomainClaimTTL` (default 7 days)
  loses its globally unique name reservation to a new `CreateWorkspaceDomain`
  from any workspace, closing the squat where an unverified claim
  permanently denied the domain's real owner; confirmed domains never
  expire. `DomainStore.CreateWorkspaceDomain` gains a `staleBefore`
  parameter carrying the cutoff.
- `CompletePasswordReset` now behaves identically on every bundled store:
  it installs the account's first password for a passwordless member
  provisioned by SSO JIT or SCIM (the memory store's behavior; the SQL
  stores previously failed). The verified email proof is the same authority
  every reset rests on, and addresses under a confirmed EnforceSSO domain
  never reach this path.
- **Breaking:** the transparent password rehash is a compare-and-swap:
  `Store.ReplacePassword` is replaced by `Store.RehashPassword`, which
  installs the stronger hash only while the hash the verification ran
  against is still in place and reports `ErrConflict` otherwise, so an
  in-flight sign-in racing a password change or reset can no longer
  resurrect the old password.
- `TouchSession` refuses a revoked session with `ErrConflict`, closing the
  race where an authentication concurrent with a revocation still succeeded
  and kept extending the idle window of a dead session.
- **Breaking:** the OAuth `client_credentials` grant is now restricted to
  administratively pre-registered confidential clients (DCR and CIMD
  registrations are refused, including `private_key_jwt`) and requires both
  a non-empty registered scope list and an explicit
  `ClientCredentialsResources` allowlist of resource URIs, enforced at
  registration, issuance, and bearer validation. An empty scope request
  grants the intersection of the registered and resource scopes instead of
  every resource scope.
- `client_credentials` access tokens carry `RevokedAt` and are individually
  revocable through the RFC 7009 endpoint; the store contract gains
  `RevokeOAuthClientAccessToken`.
- `ChangePassword` now revokes the user's sessions in the same transaction
  that installs the new password, through the new `Store.ChangePassword`
  contract (distinct from `RehashPassword`, the transparent-rehash path).
- **Breaking:** `New` fails construction when `EmailIssuanceCooldown` is set
  on a store without `EmailThrottleStore`, instead of silently disabling the
  anti-mail-bombing cooldown.
- **Breaking:** `ConfirmWorkspaceDomain` refuses with `ErrNotSupported`
  when no `DomainVerifier` is registered, unless the explicitly dangerous
  `Config.TrustActorDomainVerification` opts into trusting the actor.
- `UnlinkSSO` fails with `ErrConflict` when the identity is the user's last
  remaining authentication method, so a JIT-provisioned passwordless member
  cannot lock themselves out.
- The OIDC adapter re-discovers issuer metadata on a TTL
  (`ssoadapter.Config.MetadataRefreshInterval`, default 12 hours) instead of
  caching the first discovery for the process life, matching the SAML
  adapter's posture; a failed refresh keeps serving the last good document.

### Added

- Usernameless passkey sign-in over discoverable credentials:
  `BeginDiscoverablePasskeyAuthentication` starts a ceremony bound to no
  address (empty `allowCredentials`), and
  `FinishDiscoverablePasskeyAuthentication` resolves the account from the
  asserted credential, refusing disabled accounts and EnforceSSO domains
  and consuming the single-use ceremony like the email-first flow. This
  closes the residual enumeration signal of the per-address decoy, whose
  fabricated credential list always holds one entry. Enabled by the new
  `DiscoverablePasskeyProvider` port extension (implemented by
  `webauthnadapter`) and the new optional `PasskeyCredentialStore` store
  capability (implemented by the bundled stores).
- Bundled `githubadapter` implementing `SSOProvider` for GitHub sign-in
  (OAuth 2.0 + REST — GitHub is not an OIDC issuer, so `ssoadapter` cannot
  serve it). The subject is the stable numeric account id, the primary
  email carries GitHub's own verified flag, and the adapter is AAL1-only:
  GitHub cannot force re-authentication, so `Begin` refuses step-up
  ceremonies (`ErrStepUpUnsupported`) instead of pretending one happened.
- `Deliverable bool` on `IssuedPasswordReset`, `IssuedEmailAuthentication`,
  `IssuedEmailOTP`, and `IssuedEmailVerification` makes the
  enumeration-decoy contract explicit: send the email only when it is true,
  instead of inferring the decoy from an empty `Token`/`Code` — a naive
  host can no longer mail an empty token or branch differently on the
  decoy by accident.
- `AnyEventListener`: an `EventListener` that also implements the single
  `OnAnyEvent(ctx, name, event)` method receives every event through it —
  analytics feeds, outbox relays, and webhook dispatchers no longer
  implement 71 typed methods.
- `HTTPStatus(err) int` maps every sentinel error to its conventional HTTP
  status code, replacing the `errors.Is` ladder every host transport
  re-wrote.
- `User`, `Workspace`, and `Membership` by-ID getters with the established
  privilege scoping.
- **Breaking:** `PATs` and `SSOIdentities` take a `userID` parameter
  (`""` = the actor) so admin users read can inspect another account's
  tokens and identity links, matching `Sessions`, `Emails`, and `Passkeys`.

### Fixed

- Internal email predicates (magic-link issuance, invitation email
  matching, OIDC UserInfo claims) now follow the store cursor across all
  pages instead of reading a single fixed-limit page, so accounts holding
  more than 100 addresses no longer see silent mismatches on the tail.
- The generated PostgreSQL store no longer ships the SQLite package
  documentation or a dead `writeMu` field: the generator fails on unmatched
  replacements instead of silently skipping them.
- The SQLite and PostgreSQL OAuth stores now propagate JSON marshalling
  errors from record encoding instead of panicking the host process.
- Documentation: SSO yields AAL2 only under a satisfied `SSOAssurance`
  policy (doc.go overstated it); the OpenAPI token request advertises
  `client_credentials`; ADR-010 documents the machine-to-machine model; the
  README states the Go 1.26 requirement, the real coverage floor, and the
  host-side IP-throttling pattern over `RequestMetadata`-carrying events.
