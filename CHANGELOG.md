# Changelog

All notable changes to Credbound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). While the module is `v0`,
breaking changes may land in any release and are called out explicitly.

## Unreleased

### Security

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

- `User`, `Workspace`, and `Membership` by-ID getters with the established
  privilege scoping.
- **Breaking:** `PATs` and `SSOIdentities` take a `userID` parameter
  (`""` = the actor) so admin users read can inspect another account's
  tokens and identity links, matching `Sessions`, `Emails`, and `Passkeys`.

### Fixed

- The generated PostgreSQL store no longer ships the SQLite package
  documentation or a dead `writeMu` field: the generator fails on unmatched
  replacements instead of silently skipping them.
- Documentation: SSO yields AAL2 only under a satisfied `SSOAssurance`
  policy (doc.go overstated it); the OpenAPI token request advertises
  `client_credentials`; ADR-010 documents the machine-to-machine model; the
  README states the Go 1.26 requirement, the real coverage floor, and the
  host-side IP-throttling pattern over `RequestMetadata`-carrying events.
