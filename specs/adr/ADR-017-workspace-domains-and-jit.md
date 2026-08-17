# ADR-017 — Verified workspace domains, JIT provisioning, and SSO enforcement

## Status

Accepted.

## Context

SSO-002 deliberately forbids linking an account from an IdP-returned email
address, so every SSO user had to preexist or be invited, and SCIM was the
only provisioning path. B2B hosts expect domain capture: "everyone
@corp.example joins this workspace through this IdP". There was also no way
to force a domain through SSO, so a workspace could mandate MFA but not
prevent password sign-in entirely.

## Decision

Domains become an optional module behind the `DomainStore` capability:

- `CreateWorkspaceDomain` records a lowercase, globally unique domain in a
  pending state and returns a DNS challenge value. The library performs no
  network I/O: the host proves control (TXT record by convention) and then
  calls `ConfirmWorkspaceDomain`. Both are step-up mutations for a workspace
  administrator with settings write. Unconfirmed domains have no effect.
- A confirmed domain carries a policy: an auto-join flag with a target role
  and the SSO provider configuration it trusts, and an `EnforceSSO` flag.
- JIT provisioning: inside `FinishSSO`, when the identity is unknown, the
  IdP-verified email's domain matches a confirmed auto-join domain whose
  trusted provider configuration matches the one completing the login, and
  no account owns that address, one transaction creates a passwordless user,
  its verified email, the configured membership, and the SSO identity link.
  If any account already owns the address the login fails as an unknown
  identity: SSO-002's no-auto-link rule is preserved verbatim.
- Enforcement: `AuthenticatePassword`, `BeginPasswordReset`,
  `BeginEmailAuthentication`, and `BeginEmailOTP` reject addresses under an
  `EnforceSSO` domain with the `ErrSSORequired` sentinel before touching any
  credential. The response depends only on the domain, never on whether the
  account exists, so it introduces no enumeration oracle.

## Consequences

Domain capture works without requiring SCIM, while SCIM remains the
directory-owned path with richer lifecycle. JIT-provisioned users are
passwordless, which the AUTH-006 fix already treats identically to a wrong
password on the password path. Hosts without domain needs run without the
capability and nothing changes for them.
