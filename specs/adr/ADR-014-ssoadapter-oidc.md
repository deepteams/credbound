# ADR-014 — First-party generic OIDC adapter

- Status: accepted
- Date: 2026-08-17

## Decision

Credbound ships `ssoadapter`, a generic OpenID Connect implementation of the
`SSOProvider` port (ADR-007), so hosts stop hand-rolling the network side of
SSO. The adapter owns the protocol exchange only: issuer discovery, the
authorization code redirect with PKCE S256, state, and nonce, the code
exchange, and ID token verification against an RS256/ES256 allowlist. Google
and Microsoft Entra ID are plain OIDC issuers and use the same adapter under
their dedicated provider kinds; no per-vendor code exists.

The adapter is stateless. Everything a callback needs — state, nonce, PKCE
verifier, step-up flag, issuance time — travels as opaque `Session` bytes
inside credbound's sealed continuation, which also bounds replay with the
ceremony TTL. `ForceReauthentication` maps to `prompt=login` and `max_age=0`,
and the returned `auth_time` must be fresh, so the IdP demonstrably re-ran
its own authentication policy for step-up. The email claim is forwarded only
when the issuer asserts `email_verified=true`, because an unverified email is
user-typed input at many IdPs; identities remain keyed on issuer and subject.

Credbound keeps everything it already owned: sealed continuations, linking,
persistence, assurance levels, audit, latest use, and revocation. The default
posture is a confidential client; a PKCE-only public client must be requested
explicitly. SAML remains host-implemented against the same port for now.

## Consequences

The core module gains `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`
as dependencies of the `ssoadapter` package only; the core packages still
import neither. Hosts that need vendor-specific claims, the Microsoft
multi-tenant `common` issuer (whose per-tenant issuer defeats strict issuer
validation), or SAML continue to implement `SSOProvider` themselves.
