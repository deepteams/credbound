# ADR-010 — OAuth 2.1 and OpenID Connect server for MCP

- Status: accepted
- Date: 2026-08-16

## Context

A SaaS application using Credbound must be able to expose a remote MCP server
to its customers. The MCP client then acts on behalf of a user and must obtain a
token limited to the MCP server, workspace, and authorized operations, without
every application reimplementing an authorization server.

This capability differs from the SSO in
[ADR-007](ADR-007-sso-provider-port.md). In the existing SSO flow, Credbound is
a client of an external provider used to authenticate a user. In this ADR,
Credbound acts as an OAuth authorization server and, optionally, as an OpenID
Connect provider for application clients. A token received from an SSO provider
never becomes an MCP token and is never forwarded to the MCP server.

The MCP HTTP authorization profile relies in particular on:

- the OAuth 2.1 profile, still published as an Internet-Draft;
- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700.html);
- [RFC 8414 — Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414.html);
- [RFC 9728 — Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728.html);
- [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707.html);
- [RFC 9207 — Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207.html);
- [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591.html);
- [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02);
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  and [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html).

The [MCP authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
defines three ways to obtain a client identity: pre-registration, Client ID
Metadata Document (CIMD), and Dynamic Client Registration (DCR). It prioritizes
pre-registration, then CIMD, and retains DCR as a deprecated compatibility
mechanism. An operator must therefore be able to disable DCR, which creates a
public write surface and persistent state, while continuing to accept self-
describing CIMD clients.

Because OAuth 2.1 and CIMD are not yet stable RFCs at the date of this decision,
the implementation must isolate their protocol profile and pin the tested
revisions. An incompatible normative change will require an ADR update and
conformance tests, not silent interpretation.

## Decision

Credbound provides an optional OAuth server module, an optional OpenID Connect
profile, and an optional HTTP adapter compatible with MCP resources. The module
is disabled by default. The application explicitly selects the issuers, MCP
resources, scopes, client-identification modes, and consent policies it enables.

Credbound remains a library: it starts no HTTP server, provides no sign-in or
consent UI, and does not terminate TLS.

### Separation of responsibilities

The module distinguishes four roles:

- the Credbound authorization server authenticates the user, collects consent,
  and issues tokens;
- the optional OpenID Connect provider issues an ID Token and exposes UserInfo
  when a client requests the `openid` scope;
- the protected-resource adapter publishes RFC 9728 metadata, extracts the
  bearer token, and constructs a validated capability;
- the SaaS application's MCP server applies that capability to its tools,
  resources, and prompts.

OAuth authorizes access to a resource. OpenID Connect communicates an identity
to the client. An MCP client does not need OpenID Connect to obtain an access
token; enabling OAuth therefore does not automatically enable OIDC.

### Issuer and protected resources

An `OAuthIssuer` has a UUIDv7 and defines at least:

- the canonical, immutable HTTPS issuer URL;
- whether OpenID Connect is enabled;
- maximum code and token lifetimes;
- the CIMD policy;
- the DCR policy;
- allowed client-authentication methods;
- the OIDC signing policy; active and retiring keys are supplied through the
  injected signer when OIDC is enabled.

An `OAuthProtectedResource` also has a UUIDv7 and references exactly one issuer.
It contains its canonical `resource` URI, its workspace, publishable scopes, and
their mappings to workspace permissions.

The first version requires exactly one `resource` value per authorization and
per access token. The URI must be absolute, fragment-free, stable, and specific
enough to identify the MCP server and its tenant. When multiple workspaces are
served under one host, the canonical path includes a non-reassignable public
tenant identifier. An access token for one workspace can therefore never be
accepted by another workspace's resource.

Creating or modifying an issuer, its CIMD policy, or its DCR policy requires
`admin.settings.write` and fresh AAL2 step-up in accordance with ADR-004.
Managing a tenant-scoped MCP resource requires the built-in workspace permission
`oauth.resource.manage`, granted to `admin` by default and extensible through
the ADR-009 role catalog. A workspace administrator cannot weaken the issuer's
global policy.

### Discovery and endpoints

The `oauthhttp` adapter can mount the following endpoints without imposing a
router:

- RFC 8414 OAuth metadata;
- `/authorize` and `/token`;
- `/revoke` according to RFC 7009;
- RFC 9728 protected-resource metadata;
- `/register` only when DCR is enabled;
- OIDC metadata, JWKS, and `/userinfo` only when OIDC is enabled.

Metadata advertises exactly the active capabilities. It contains at least
`code_challenge_methods_supported: ["S256"]` and
`authorization_response_iss_parameter_supported: true`.
Authorization-server metadata omits the optional aggregate `scopes_supported`
field because scopes are resource-specific; each RFC 9728 protected-resource
document publishes its exact scope catalog instead.

Every MCP resource publishes its RFC 9728 metadata and, when authorization is
missing, returns a challenge of the form:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
                         scope="documents.read"
```

The `scope` field describes the minimum required by the current operation. A
valid but insufficient token produces `403 Forbidden` with `insufficient_scope`.

### Independent client-discovery policies

Pre-registration is always available to authorized operators. CIMD and DCR are
independent capabilities:

| CIMD | DCR | Metadata and behavior |
|---|---|---|
| disabled | `disabled` | only pre-registered clients are accepted; no `registration_endpoint` |
| enabled | `disabled` | `client_id_metadata_document_supported: true`; no `registration_endpoint` |
| enabled or disabled | `protected` | `registration_endpoint` is published; an initial access token is required |
| enabled or disabled | `open` | `registration_endpoint` is published without an initial access token; explicit high-risk opt-in |

The safe default is disabled CIMD and DCR `disabled`. For a SaaS application
that opens an MCP server to unknown clients, the recommended configuration is
enabled CIMD and DCR `disabled`. DCR `open` mode is never inferred from a
development mode and has no implicit fallback.

When DCR is disabled, `registration_endpoint` is absent from metadata, and the
conventional route returns `404 Not Found` if called anyway. This does not affect
pre-registered clients or CIMD Client Identifier URLs.

### Deterministic client resolution

Upon receiving an authorization request, Credbound resolves the `client_id` in
the following order:

1. exact match with a pre-registered or DCR-created client;
2. exact match with an already preapproved CIMD Client Identifier URL;
3. if CIMD is enabled, secure loading of the document at a valid `https` URL;
4. otherwise, `unauthorized_client`.

An authorization request never triggers DCR registration. DCR is available only
through its RFC 7591 endpoint. Opaque identifiers generated by Credbound are
UUIDv7 values and never begin with `https://`, avoiding collisions with Client
Identifier URLs. A pre-registered URL explicitly retains its type; its appearance
alone cannot determine its source.

The resolved client is then checked against the registered redirect URI,
resource, scopes, current workspace permissions, and user consent. Resolving a
client identity grants it no scope and no workspace access. Additional
client/domain allowlists are host policy applied before the consent is completed.

### Client ID Metadata Documents

The CIMD policy has three modes independent of DCR:

- `disabled`: no dynamic discovery by URL;
- `allowlist`: only explicitly approved domains or Client Identifier URLs are
  loaded;
- `public_web`: any conforming public URL may be evaluated, subject to trust and
  security rules.

A Client Identifier URL:

- must use HTTPS and have a path;
- contains no userinfo, fragment, or `.` or `..` segment;
- is compared as an exact string, without normalizing ports, case, trailing
  slashes, or encoding;
- directly returns a JSON document with `200 OK`, without redirection;
- contains at least a `client_id` exactly equal to the loaded URL, a
  `client_name`, and `redirect_uris`.

The CIMD loader is a dedicated network port with a secure adapter. In production
it:

- rejects every special, private, link-local, loopback, and infrastructure-
  metadata address for every DNS resolution and connection;
- uses only explicitly supported schemes and follows no redirect;
- applies a timeout, process-local concurrency limit, and a maximum document
  size of 5 KiB; issuer/domain rate limits remain a host responsibility;
- validates the JSON type, structure, repeated values, field counts, and each
  string's size;
- applies the same address, redirect, timeout, and size protections when the
  bundled JWT verifier loads a declared `jwks_uri`;
- ignores logo metadata and never makes the browser load a remote document
  asset.

A valid document is cached according to HTTP directives within minimum and
maximum bounds configured by Credbound. An error or invalid document is not
cached. If no valid cache entry exists and reloading fails, authorization fails
closed.

The cache stores the exact URL, validated metadata, fingerprint, load and
expiration times, and an internal UUIDv7 if persisted by the store. It does not
turn the CIMD client into a DCR registration. A sensitive change to
`redirect_uris`, `token_endpoint_auth_method`, `grant_types`, scopes, or keys
invalidates affected consents and requires new authorization.

The consent screen supplied by the SaaS application must display:

- the declared client name and hostname of the Client Identifier URL;
- the exact redirect hostname, with a stronger warning for `localhost`;
- the target MCP resource and workspace;
- requested scopes and an understandable description of their effect.

The declared name and logo are never proof of trust. The host service may apply
an allowlist, denylist, domain reputation, or additional manual validation.

### Dynamic Client Registration

DCR follows RFC 7591 and remains an optional compatibility feature. Its policy
belongs to the issuer:

- `disabled`: no advertised or active endpoint;
- `protected`: every request requires an expiring, revocable initial access
  token limited to the issuer;
- `open`: no prior relationship is required, with stronger quotas and rate
  limiting.

`protected` mode is recommended when a legacy client requires DCR. An initial
access token contains at least 256 bits of entropy, is returned in plaintext only
once, and only its HMAC digest is persisted. Creating or revoking one requires
`admin.settings.write` and fresh AAL2 step-up.

The first DCR version:

- accepts only the code flow, `response_type=code`, and policy-compliant redirect
  URIs;
- requires `application_type=native` or `web` and applies the corresponding
  rules;
- grants no scope absent from the server catalog;
- generates a UUIDv7 `client_id` bound to the issuer;
- supports `token_endpoint_auth_method=none` for public clients and
  `private_key_jwt` for clients capable of protecting a key;
- may support `client_secret_basic` and issue a symmetric secret only for
  pre-registration or `protected` DCR explicitly allowed to do so, never for
  `open` DCR;
- does not support `client_secret_post`;
- allows administrative client disabling and revocation.

Any client secret has 256 bits of entropy, is displayed only once, and only an
HMAC digest is persisted. Later self-management of client metadata, such as RFC
7592, is outside the initial scope.

Protected DCR enforces the initial access token's registration count. Open DCR
enforces a configured maximum of active DCR clients per issuer; disabling a
client releases that capacity without deleting its audit history. Network and
domain rate limits remain mandatory at the host edge. Automatic inactivity
expiry is outside v0; an operator reviews and disables unused clients through
the administration API.

### Authorization Code and PKCE

The first version supports `authorization_code` with PKCE `S256`. PKCE is
mandatory for every public and confidential client. Implicit and resource owner
password grants are rejected. `client_credentials` cannot represent a user and
remains outside the initial delegated MCP profile.

An authorization request must contain:

- an unambiguously resolved issuer and `client_id`;
- a `redirect_uri` exactly equal to a validated value;
- an S256 `code_challenge`;
- exactly one known `resource` URI;
- scopes known to that resource;
- client-managed `state` and, for OIDC, a `nonce` as required by the flow.

Credbound includes `iss` in authorization responses, including redirectable
errors, and advertises it in metadata. An error involving an unknown client or
unvalidated redirect URI is rendered locally: the browser is never redirected
to an unapproved target.

The authorization code is random, single-use, and bound to the client, redirect
URI, PKCE verifier, user, workspace, resource, scopes, and consent. It expires
after five minutes by default, and only its HMAC digest is stored.

### Scopes, RBAC, and workspace isolation

Every MCP scope is registered by the host service with a consent description
and one or more `WorkspacePermission` values. The reserved `openid`, `profile`,
`email`, and `offline_access` scopes belong to the OAuth/OIDC module and cannot
be redefined as application permissions.

Effective scopes are the intersection of:

1. those requested by the client;
2. those allowed for that client by local policy;
3. those supported by the resource;
4. those allowed by the membership's current permissions;
5. those explicitly consented to by the user.

A CIMD document or DCR request can never create a scope or force it to be
granted. The membership role is not copied into the token as an authority;
mapped permissions are reevaluated when the token is validated. An unknown role,
suspended membership, disabled user, disabled resource, or different workspace
fails closed.

### Consent and step-up

A persistent `OAuthGrant` is identified by UUIDv7 and bound to the issuer,
client, user, resource, workspace, and consented scopes. A scope increase,
sensitive client-metadata change, or resource change requires new consent.

Explicit consent is the default. Only a pre-registered client may be marked
`trusted` to apply a reduced-consent policy. This mutation requires
`admin.settings.write`, fresh AAL2 step-up, and an audit. A CIMD or DCR client
can never declare itself `trusted`.

Interactive authentication reuses existing Credbound methods: password, TOTP,
passkey, or SSO. The resource may require a minimum AAL and authentication
freshness per scope. A sensitive write or administration permission can thus
trigger step-up before consent.

The host application renders the UI but cannot construct a grant directly.
Credbound issues a sealed continuation containing the validated context and
verifies that continuation when consent is accepted or denied.

### Access tokens, refresh tokens, and revocation

The first version issues opaque access tokens containing at least 256 bits of
entropy. Only their HMAC digest is persisted. The MCP server transforms them
into `OAuthAuthentication` through a Credbound operation; it never accepts a
claims structure supplied directly by the HTTP adapter.

An access token is bound to exactly one issuer, client, user, workspace,
`resource`, scope set, and grant. Its default lifetime is fifteen minutes. On
every request, validation checks expiration, revocation, the exact resource,
scopes, and the state of the client, user, membership, and grant.

Refresh tokens are optional and issued only when policy allows `offline_access`.
They are opaque, stored as HMAC digests, bound to the same resource, and grouped
into families. Every use rotates the token. Reusing an old token revokes the
entire family and produces a security audit. Reduced permissions produce reduced
access tokens; scopes can never be increased without new authorization.

Revoking a grant, client, membership, user, resource, or issuer atomically
revokes the relevant refresh tokens. Opaque access tokens become immediately
invalid on their next validation. No raw code, access token, refresh token,
client secret, or initial access token appears in an audit, event, OTEL
attribute, or access log.

### OpenID Connect profile

OIDC is enabled separately per issuer. A request containing `openid` receives a
signed ID Token and may access UserInfo according to the consented scopes.
Without `openid`, the flow remains an OAuth flow and no ID Token is issued.

The `sub` claim is pairwise, stable for the client's sector, and irreversible.
It never directly exposes `User.ID`. `email` and `email_verified` are issued only
with the `email` scope and according to the address's actual state. Workspace,
role, and permission information is not included by default in the ID Token or
UserInfo.

Version v0 does not implement `sector_identifier_uri`. Consequently, every
client registered under an OIDC-enabled issuer must use redirect URIs with one
hostname, including clients whose registered scope list is empty. This keeps
the pairwise subject deterministic if such a client later requests `openid`.

ID Tokens contain and validate at least `iss`, `sub`, `aud`, `exp`, `iat`, and
`nonce` when requested. Credbound may also publish `auth_time`, `acr`, and `amr`
from the actual `Authentication`. Signing keys are supplied by a port, identified
by `kid`, published through JWKS, and rotated with enough overlap to validate
unexpired tokens.

This OIDC-provider capability does not change the ADR-007 SSO link and permits
no automatic email-based correlation with an external provider.

### Redirect URIs and client authentication

All redirect URIs are registered and compared exactly. HTTPS is mandatory
outside native applications. For a native application, HTTP is limited to
`127.0.0.1` or `[::1]` with an ephemeral port according to the applicable
profile; domain names that resolve to loopback do not receive this exception.
`localhost` may be tolerated for MCP compatibility with a visible warning, but
literal loopback IP addresses are preferred.

URIs containing a fragment, userinfo, or an unauthorized scheme are rejected.
Native custom schemes are outside v0. Native clients may use HTTPS or an HTTP
loopback redirect only; selecting `application_type=native` never relaxes this
scheme policy.

Public clients use `token_endpoint_auth_method=none` and PKCE. Confidential
clients use `private_key_jwt` or, only when pre-registered or created through an
authorized protected DCR flow, `client_secret_basic`. A public key declared by
CIMD is reloaded with the same network protections as the document. A key change
may invalidate grants and tokens according to the issuer's risk policy.

### Persistence, transactions, and events

The module extends the in-memory, SQLite, and PostgreSQL stores. Goose migrations
and sqlc queries cover at least issuers, resources, clients, the CIMD cache,
initial access tokens, grants, codes, access tokens, refresh-token families,
consents, and referenced keys. Every internal identifier created by Credbound is
a UUIDv7.

Mutations follow ADR-008: validation, transaction, hooks, audit, commit, then
events. Minimum events are:

- `oauth.client.registered`, `oauth.client.disabled`;
- `oauth.cimd.resolved`, `oauth.cimd.rejected`, `oauth.cimd.changed`;
- `oauth.authorization.granted`, `oauth.authorization.denied`;
- `oauth.token.issued`, `oauth.token.refreshed`, `oauth.token.revoked`;
- `oauth.refresh_token.reuse_detected`;
- `oauth.consent.revoked`.

High-volume denials may be aggregated for observability so that the persistent
audit does not become a denial-of-service vector. Security audits retain internal
identifiers, client source, issuer, resource, workspace, scopes, and outcome,
never secrets or unnecessary raw personal metadata.

Transactional hooks let the host service synchronize quotas, licenses, or an
outbox. A hook can never modify validated scopes, construct a token, or bypass
consent.

### Ports and host-service responsibilities

The core provides use cases, invariants, error types, and authenticated
capabilities. Optional adapters provide the OAuth HTTP codec, secure CIMD loader,
and stores. Ports cover at least the clock, entropy, HMAC, OIDC signing, and
controlled HTTP loading.

The host service remains responsible for:

- TLS, trusted proxies, security headers, and global request limits;
- session cookies, CSRF, and sign-in/consent UI;
- distributed rate limiting and upstream abuse protection;
- exact public issuer and resource URIs;
- translating scopes into understandable descriptions;
- mounting middleware on every protected MCP endpoint;
- commercial configuration determining which workspaces may enable MCP.

An invalid public-URL or proxy configuration must make adapter construction
fail; Credbound does not infer an issuer from a request's `Host`, `Origin`, or
forwarding headers.

## Initially out of scope

- hosting an MCP server or interpreting MCP messages;
- acting as an authorization server for a protocol other than HTTP;
- implicit grant and resource owner password grant;
- client credentials for the user-delegated MCP profile;
- device authorization grant, CIBA, PAR, JAR, and RAR;
- dynamic client management according to RFC 7592;
- remote RFC 7662 introspection and network separation between the authorization
  server and resource server;
- self-contained JWT access tokens;
- issuer federation or delegation to an external authorization server;
- a Credbound-hosted CIMD Service for development clients;
- client or software attestation;
- host-service consent UI and session management.

These exclusions do not prevent later ADRs. They avoid mixing the user-facing
MCP need with machine-to-machine credentials or a general identity platform in
the first version.

## Consequences

A SaaS application can open an MCP server to clients with no prior relationship
through CIMD while keeping DCR disabled. Legacy clients requiring DCR can be
supported per issuer in protected mode or, by explicit choice, open mode.
Discovery reflects this choice unambiguously.

This decision adds a significant security subdomain: consents, codes, tokens,
revocation, OIDC keys, hostile network loading, and tenant isolation. The
implementation includes protocol error tests, SSRF resolution and special-
address tests, replay tests for codes, refresh tokens, and client assertions,
and cross-workspace tests. Maintained-code coverage remains strictly above 90%.

Depending on Internet-Drafts requires tracking OAuth 2.1, MCP, and CIMD versions.
Adapters advertise only what they actually implement, and the library version
remains the sole version of the Go contract.

Accepting this ADR requires adding the corresponding requirements to the PRD and
public operations to `specs/API.md` before implementation.

## Rejected alternatives

- making DCR mandatory for every MCP client;
- disabling CIMD when DCR is disabled;
- silently registering a DCR client during `/authorize`;
- treating every string beginning with `https://` as a CIMD client without a
  persistent type or policy;
- directly reusing an SSO token or forwarding it to an upstream API;
- issuing a token valid for multiple workspaces or resources;
- copying roles into the token without reevaluating permissions;
- using self-contained JWTs in the first version despite immediate-revocation
  requirements;
- exposing `User.ID` as the OIDC `sub` claim;
- loading CIMD logos from the user's browser;
- starting an HTTP server from the library.
