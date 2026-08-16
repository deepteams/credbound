# ADR-006 — Multiple email addresses, latest activity, and client audit

- Status: accepted
- Date: 2026-08-16

## Decision

Email addresses are separate, globally unique entities identified by UUIDv7. A
user has exactly one primary address. Added addresses remain inactive for
sign-in until a random, time-limited proof is validated; only an HMAC fingerprint
is persisted.

`last_seen_at` is updated on every successful authentication. The update shares
the authentication audit event's transaction.

The host service may call `RecordAudit`, but Credbound constructs the event
identity, actor, and timestamp. The service controls only validated business
fields and therefore cannot impersonate a user or backdate the entry.

## Consequences

The host service remains responsible for delivering the verification proof by
email. A compromised address cannot be linked silently. Global application
events require an administration permission.
