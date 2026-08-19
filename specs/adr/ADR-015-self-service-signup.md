# ADR-015 — Self-service signup

## Status

Accepted.

## Context

Every user until now was created by an authenticated administrator, an
invitation, or `Bootstrap`. A SaaS host offering public registration had to
compose those primitives itself and inevitably re-invented the
enumeration-resistance and atomicity invariants Credbound exists to
centralize.

## Decision

`SignUp(ctx, SignUpInput)` is a first-class, host-enabled operation:

- It is off unless `Config.SignUp` is set, and it requires the optional
  `SignupStore` capability; otherwise it returns `ErrNotSupported`.
- One store transaction creates the user, their primary email address, their
  password credential, their workspace, and their `admin` membership. No
  instance role is ever granted (unlike `Bootstrap`).
- The primary address starts unverified, and the result carries an
  `IssuedEmailVerification` token the host delivers; the account cannot
  authenticate by email address until the address is confirmed. A host that
  accepts the risk sets `Config.SignUp.AutoVerifyEmail`, which verifies the
  address immediately and additionally returns an AAL1 `Authentication`.
- Enumeration resistance follows the reset/magic-link pattern: when the
  address already belongs to an account, the operation performs the same
  hashing and identifier generation, audits the collision, and returns a
  zero-valued result with `ExistingAccount: true` and no error. The host
  answers the end user identically and may deliver an "already registered"
  notice to the address instead of a verification token.
- The password goes through the same validation pipeline as every other
  acceptance path, including `Config.PasswordPolicy`.

## Consequences

Hosts get public registration without touching store internals. Third-party
stores keep compiling: signup is a capability interface, not a widening of
`Store`. The workspace-per-signup model matches the bootstrap topology; hosts
that want invite-only growth simply leave `Config.SignUp` nil.
