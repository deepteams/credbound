# ADR-018 — First-party SAML service-provider adapter

- Status: accepted
- Date: 2026-08-17

## Context

Since ADR-007 the `SSOProviderKind` enum has carried a `saml` value, and
SSO-001 claims SAML support, but the library shipped no implementation: every
host wanting SAML had to implement the `SSOProvider` port itself, including
XML signature validation — the single most dangerous part of SAML, with a
long public history of signature-wrapping and comment-truncation breaks.
ADR-014 removed the equivalent burden for OIDC; SAML remained the gap.

## Decision

Credbound ships `samladapter`, a SAML 2.0 service-provider implementation of
the `SSOProvider` port built on `github.com/crewjam/saml`. The protocol and
XML-DSig verification are delegated to that library — no hand-rolled
signature code — and the adapter wraps them in credbound's ceremony contract
while tightening the defaults: the response must name the ceremony's request
id in `InResponseTo` (compared in constant time, so unsolicited and
IdP-initiated responses are rejected), must contain exactly one assertion,
and must carry an `AudienceRestriction` naming the SP entity ID (crewjam
alone accepts assertions without one). Issuer, destination, recipient, and
the validity window (with a small clock skew) are validated against the IdP
metadata and the configured ACS URL. The NameID becomes the credbound
subject, so its format must be persistent or unspecified; transient NameIDs
cannot key a durable identity and are rejected unless the host opts in. The
email attribute is read from the standard names, forwarded only when it
parses as a valid address, and dropped — never fatal — otherwise. Validation
errors never include assertion XML.

The adapter is stateless like `ssoadapter`: the AuthnRequest id travels as
opaque `Session` bytes inside credbound's sealed continuation, which also
bounds replay with the ceremony TTL. Static `MetadataXML` is the primary
configuration path — parsed eagerly, no network dependency; a `MetadataURL`
is supported for IdPs that rotate certificates frequently and is fetched
lazily, once, over HTTPS with a 10-second timeout and a size cap, under the
same SSRF posture as `ssoadapter`. An optional SP key pair signs
HTTP-Redirect AuthnRequests. `ForceReauthentication` maps to
`ForceAuthn="true"`, but SAML gives the SP no `auth_time` equivalent to
verify afterwards, so step-up depends on the IdP honoring the flag — a
weaker guarantee than the OIDC adapter's, stated in the godoc.

Credbound keeps everything it already owned: sealed continuations, linking,
persistence, assurance levels, audit, latest use, and revocation.

## Consequences

SSO-001's SAML claim becomes real: hosts register `samladapter.New` output in
`Config.SSOProviders` and never touch XML-DSig. The core module gains
`github.com/crewjam/saml` (with its `goxmldsig`, `etree`, and
`xml-roundtrip-validator` graph) as dependencies of the `samladapter` package
only; the core packages import none of them. Metadata rotation is a host
redeploy with fresh `MetadataXML`, or — when `MetadataURL` is used — a
provider restart, since a fetched document is cached for the provider's
lifetime. Hosts needing IdP-initiated SSO, transient-only IdPs beyond the
explicit override, artifact binding, or single logout continue to implement
`SSOProvider` themselves.
