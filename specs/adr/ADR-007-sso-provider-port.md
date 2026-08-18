# ADR-007 — Optional SSO by provider

- Status: accepted
- Date: 2026-08-16

## Decision

Credbound provides an `SSOProvider` port and a common lifecycle for Google,
GitHub, Microsoft, OpenID Connect, and SAML. Every provider instance carries a
UUIDv7 configuration injected by the host service, which selects the adapters
and secrets enabled for its SaaS application.

An external identity is indexed by configuration, issuer, and subject. Initial
linking requires an existing interactive session; automatic email-based matching
is not allowed. Validated SSO authentication is AAL1 by default; only a
registered `Config.SSOAssurance` policy — verifying the asserted authentication
context or explicitly trusting the provider — lifts it to AAL2, so an
unverified IdP cannot satisfy an MFA requirement on its own word. For step-up,
the port receives `ForceReauthentication=true` so that the IdP applies its own
MFA policy.

## Consequences

The core remains independent of network SDKs and their secret rotation. Provider
adapters implement redirection, callbacks, and cryptographic validation;
Credbound handles sealed continuation, linking, assurance, audit, latest use,
and local revocation.
