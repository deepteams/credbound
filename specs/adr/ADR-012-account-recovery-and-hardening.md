# ADR-012 — Account recovery, abuse control, and audit hardening

## Status

Accepted.

## Context

The initial release deliberately deferred password reset, delegated
brute-force throttling to the host, offered no invitation flow, and recorded
an append-only audit log whose integrity relied on database constraints alone.
Each host service was starting to reimplement these invariants, which is the
duplication Credbound exists to remove.

## Decision

### Single-use email-proof tokens

Password reset (`cbr_`), magic-link authentication (`cbl_`), and workspace
invitations (`cbi_`) reuse the email-verification token shape:
`<prefix>_<uuidv7>_<43-char base64url secret>` with 256 bits of entropy. Only
an HMAC-SHA256 digest keyed by `SecretKey` with a per-purpose domain prefix is
persisted; consumption is guarded by an atomic `used_at IS NULL` update. The
initiation paths perform the same identifier and secret generation for unknown
addresses so response timing does not reveal account existence; the host must
answer the end user identically in both cases.

Completing a reset applies an explicit revocation policy inside one store
transaction: the password is replaced, every PAT and OAuth grant of the user
is revoked, the account's other pending resets are deleted, and its lockout
counter is cleared. Host-owned sessions remain the host's responsibility.
Passkeys and the TOTP factor deliberately survive a reset: they are stronger,
phishing-resistant factors and their loss has its own recovery path.

A magic link authenticates only a verified address, returns AAL1 with
`SecondFactorRequired` like a password login, and `MethodEmail` counts as
interactive.

### Invitations

An invitation binds an email address, a workspace, and a role chosen from the
registered catalog. Acceptance is either explicit (an authenticated user who
owns the invited address as a verified email) or a registration that creates
the account atomically with the invited address pre-verified — delivery of the
token proved control of the mailbox. Admin-set passwords are no longer needed
to onboard invitees. One pending invitation per address and workspace is
enforced by a partial unique index.

### Built-in lockout

`credbound_login_throttles` counts consecutive password and TOTP failures per
account inside the same transaction as the failure audit. Reaching
`MaxFailedLogins` (default 10) locks the account for `LockoutDuration`
(default 15 minutes); a locked attempt still performs the dummy password
derivation and returns `ErrLocked` without confirming unknown accounts. A
successful password, TOTP, recovery-code, magic-link, or email-OTP
authentication — and a completed password reset — clears the counter, but only
once the sign-in is complete: while a second factor is pending, a correct
first factor (password, magic link, or email OTP) leaves the counter untouched
so it cannot reset the guessing budget between TOTP attempts, and a locked
account refuses magic-link and email-OTP redemption with `ErrLocked` (the
redeemed token proved mailbox control, so no enumeration oracle opens). An
expired lockout restarts the window instead of instantly re-locking. Hosts
that throttle upstream disable the feature with a negative `MaxFailedLogins`.

### Workspace MFA policy

`Workspace.RequireMFA` rejects interactive sessions below AAL2 in
`Authorize`/`AuthorizePermission` with `ErrStepUpRequired`, so hosts can
prompt for the second factor. Non-interactive credentials (PATs, whose
creation already required a step-up) are exempt.

### Audit request context and hash chain

`WithRequestMetadata` carries a sanitized, length-bounded client IP address and
user agent through the context into every audit event; Credbound never reads
transport headers. Audit timestamps are truncated to microseconds so hashes
recompute identically after a PostgreSQL round trip.

Every audit event is chained: the store assigns `sequence`, `previous_hash`,
and `hash = SHA-256(previous ‖ length-prefixed fields)` inside the commit
transaction, and a seeded singleton `credbound_audit_chain` row serializes the
head (`FOR UPDATE` on PostgreSQL). `VerifyAuditChain` recomputes the chain and
compares it with the head, returning `ErrAuditCompromised` on any edited,
removed, or reordered event. Events recorded before the migration keep a NULL
sequence and stay outside the chain.

### Revocation and factor visibility

`RevokeUserCredentials` revokes every PAT and OAuth grant of a user in one
atomic operation — by the user with step-up after a suspected compromise, or by
an instance administrator with users write. `Passkeys` and `TOTPStatus` expose
credential metadata (never secret material) so hosts can build security pages;
reading another account requires admin users read.

## Consequences

- The `Store` interface grows accordingly; v0 allows this breaking change and
  all bundled stores implement the new contract.
- The `hardening` migration (20260817090000) is additive and seeds the audit chain head.
- Symmetric-key and pepper rotation limitations from OPS-001 apply unchanged
  to the new token digests.
