# ADR-016 — Server-side sessions

## Status

Accepted.

## Context

The library returned an in-memory `Authentication` capability and left every
session concern to the host. That boundary kept transport ownership clean but
had a real cost: the revocation guarantees of `CompletePasswordReset`,
`DisableUser`, and `RevokeUserCredentials` stopped at PATs and OAuth grants,
"log out everywhere" and device listings had to be rebuilt by every host, and
the most security-sensitive piece of an integration was the one Credbound did
not help with.

## Decision

Sessions become an optional module behind the `SessionStore` capability:

- `CreateSession` persists an immutable snapshot of the actor's
  `Authentication` (method, level, authenticated-at, second-factor flag)
  plus device metadata from `RequestMetadata`, behind an opaque
  `cbs_<uuidv7>_<secret>` token returned exactly once. Only an HMAC digest
  under the derived key (domain `session:`) is stored.
- `AuthenticateSession` validates the digest in constant time, enforces
  expiry and revocation, re-checks user disablement, touches last-seen
  transactionally, and returns the snapshot plus the `Session` record.
- Sessions never change assurance level in place. After `VerifyTOTP` or any
  AAL transition the host mints a new session and revokes the old one; the
  rotation doubles as fixation protection.
- `Sessions` lists a user's sessions (self, or another user for a step-up
  administrator with users read); `RevokeSession` and `RevokeUserSessions`
  follow the same authorization shape as PAT revocation.
- When the store supports sessions, `CompletePasswordReset`, `DisableUser`,
  and `RevokeUserCredentials` revoke the user's sessions inside the same
  transaction, closing the previously documented gap.
- Default TTL is 30 days, configurable through `Config.SessionTTL`.

Cookies, CSRF, and transport binding remain host-owned: the library stores
and validates sessions, the host decides how the token travels.

## Consequences

Hosts stop hand-rolling the riskiest part of the integration, and library
revocation semantics finally extend to interactive sessions. Stores that do
not implement `SessionStore` keep working; every session operation then
returns `ErrNotSupported`.
