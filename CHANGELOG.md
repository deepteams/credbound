# Changelog

All notable changes to Credbound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). While the module is `v0`,
breaking changes may land in any release and are called out explicitly.

## Unreleased

### Security

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
  contract (distinct from `ReplacePassword`, which remains the
  transparent-rehash path).
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
