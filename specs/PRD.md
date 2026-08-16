# PRD — Credbound

## 1. Problem

Go services reimplement identity, authentication factors, PATs, and access
control too often. This duplication increases delivery costs and creates
security inconsistencies that are difficult to audit.

Credbound provides a reusable, testable, transport-independent core.

## 2. Scope

### Included in the initial version

| ID | Requirement | Acceptance criterion |
|---|---|---|
| AUTH-001 | Local account | A normalized address and password can authenticate an active user without revealing whether the account exists. |
| AUTH-002 | Password storage | Passwords are derived with Argon2id using a random salt and versioned parameters; a hash is renewed after successful authentication when the policy changes. |
| AUTH-003 | Passkey | The library can start and finish WebAuthn registration and authentication ceremonies while requiring user verification. |
| AUTH-004 | 2FA | A user can enable TOTP after confirming a valid code and receives single-use recovery codes. |
| AUTH-005 | Step-up | A sensitive operation can require interactive AAL2 authentication newer than a configurable duration. |
| AUTH-006 | Enumeration resistance | An unknown identifier and an invalid password produce the same public error and both perform a password derivation. |
| USER-001 | Latest activity | `last_seen_at` reflects the latest successful authentication across all factors. Its update and the authentication audit are atomic. |
| EMAIL-001 | Multiple email addresses | A user may own multiple globally unique addresses, exactly one of which is primary. A secondary address becomes usable for sign-in only after verification. |
| EMAIL-002 | Verification | Adding an address issues a random token displayed once to the host service; only its HMAC is persisted, and the token expires. |
| EMAIL-003 | Management | Adding an address requires recent interactive authentication; selecting the primary address or removing an address requires AAL2 step-up. The primary address and the last verified address cannot be removed. |
| PAT-001 | Creation | A PAT uses at least 256 bits of entropy, is returned in plaintext only once, and only an HMAC digest is persisted. |
| PAT-002 | Multiplicity | A user may own multiple named PATs that can be revoked independently. |
| PAT-003 | Visibility | Lists expose metadata, prefix, creation time, expiration, and latest use, but never the secret. |
| TENANT-001 | Isolation | Every resource-access authorization is evaluated for an explicit `workspace_id`. |
| TENANT-002 | Workspace lifecycle | An AAL2 user can create a workspace and becomes its `admin`; authorized administrators can rename or disable it atomically. A disabled workspace denies every tenant-scoped capability. |
| TENANT-003 | Membership lifecycle | Authorized administrators can add, suspend, reactivate, and remove local memberships. SCIM-managed memberships remain directory-owned and the last active workspace administrator cannot be removed, suspended, or demoted. |
| TENANT-004 | Revocation cascade | Disabling a workspace or suspending/removing a membership atomically revokes the affected workspace-scoped PAT and OAuth credentials. |
| RBAC-001 | Workspace roles | The `admin` and `member` roles are provided; the host service may register additional roles and permissions when constructing the `Manager`. |
| RBAC-002 | Permission changes | Only a workspace administrator with a valid step-up may grant or modify a role. |
| RBAC-003 | Permission-based authorization | The canonical check uses a workspace permission. Inheritance is validated without cycles, `admin` receives all registered permissions, and an unknown role fails closed. |
| USER-002 | Administrative lifecycle | An instance administrator can disable or re-enable a global user. A disabled user cannot authenticate or authorize, and the last enabled root administrator is protected. |
| ADMIN-001 | Instance administration | Instance administration is separate from workspace RBAC and provides `root`, `developer`, `support`, `marketing`, and `sales`. |
| ADMIN-002 | First administrator | The first account created by `Bootstrap` atomically receives the instance-level `root` role. |
| ADMIN-003 | Permissions | Each instance role maps to explicit permissions; services authorize an action by permission rather than through ad hoc role-name comparisons. |
| ADMIN-004 | Elevation and downgrade | Only a `root` may grant, modify, or remove an instance-administration role. The operation is audited and protected by step-up. |
| ADMIN-005 | Mutation protection | Any administrative write or deletion concerning a user, workspace, role, permission, or global setting requires fresh AAL2, except for a trusted local request. |
| ADMIN-006 | Local exception | The localhost exception is determined by the server adapter from the actually observed remote address and trusted-proxy configuration, never from a header or URL freely supplied by the client. |
| ADMIN-007 | Audited access | Every opening or operation of the administration interface, whether allowed or denied, produces an audit event. |
| AUDIT-001 | Append-only audit | Every authentication, factor/PAT management operation, and permission change produces an immutable timestamped event with actor, action, target, workspace, and outcome. |
| AUDIT-002 | Fail closed | A sensitive mutation fails if its audit event cannot be persisted atomically. |
| AUDIT-003 | Application events | The consuming service may record an event through the Manager. It supplies the action, target, workspace, outcome, and reason; Credbound enforces the authenticated actor, UUIDv7, and timestamp. A global event requires an administration permission. |
| SSO-001 | Providers | The core supports registered Google, GitHub, Microsoft, OpenID Connect, and SAML providers through a common port. Each SaaS application chooses which providers to enable. |
| SSO-002 | Explicit linking | An external identity is linked from an existing interactive session. Credbound never automatically associates an account from an email address returned by the IdP. |
| SSO-003 | Assurance | Validated SSO authentication produces AAL2. For step-up, the provider receives a requirement to force reauthentication and its own MFA. |
| SSO-004 | Stable identity | The link relies on the UUIDv7 configuration, issuer, and subject triplet, never on email alone. Latest uses are visible and auditable. |
| SCIM-001 | Optional activation | The core exposes SCIM only when the store implements `SCIMStore`. The SaaS application enabling provisioning explicitly mounts the `scimhttp` adapter. |
| SCIM-002 | Tenant-scoped domain | Every SCIM configuration, credential, user, and group has a UUIDv7 and remains limited to one configuration and its workspace. A user's SCIM identifier is distinct from their global `User.ID`. |
| SCIM-003 | User lifecycle | SCIM can create a passwordless user, explicitly adopt a local user, replace, suspend, reactivate, and logically deprovision a membership without disabling the global account. |
| SCIM-004 | Source of truth | A membership identifies `local` or the UUIDv7 of its SCIM configuration as its source. An ordinary local mutation cannot overwrite a SCIM-managed membership. |
| SCIM-005 | Groups and roles | SCIM groups are persisted. Only configured mappings to a known role may change the role; an ambiguous mapping or unknown member fails closed. |
| SCIM-006 | Service credentials | Credentials have at least 256 bits of entropy, are displayed only once, can be rotated and revoked, and only their HMAC is persisted. They never represent a user. |
| SCIM-007 | SCIM 2.0 HTTP | `scimhttp` provides discovery, `Users`, `Groups`, `.search`, supported filters, opaque cursors, and `application/scim+json` errors. Password and Bulk are rejected and not advertised. |
| SCIM-008 | Atomicity and integration | Every provisioning mutation, its corresponding transactional hook, and its service audit are atomic; typed events are emitted only after commit. |
| OAUTH-001 | Optional activation | The core exposes the OAuth server only when `Config.OAuth` is provided and the store implements `OAuthStore`. |
| OAUTH-002 | Tenant-scoped MCP resource | Every protected resource belongs to an issuer and a workspace. An access token is bound to one `resource` URI and cannot be replayed in another workspace. |
| OAUTH-003 | Client registration | Pre-registration, CIMD, and DCR are independent. CIMD may remain active while DCR is `disabled`; DCR also provides `protected` and `open` modes. |
| OAUTH-004 | Secure CIMD | Client Identifier URLs use HTTPS, are compared exactly, are fetched without redirects, and are protected against SSRF, DNS rebinding, oversized responses, and changing metadata. |
| OAUTH-005 | Authorization Code | The only initial user flow is `authorization_code` with PKCE `S256`, an exact redirect URI, `state`, an identified issuer, and a mandatory `resource`. |
| OAUTH-006 | Tokens | Codes and tokens are opaque, have at least 256 bits of entropy, and are persisted only as HMACs. Refresh tokens rotate, and reuse revokes the family. |
| OAUTH-007 | Consent and scopes | Consent is bound to the user, client, resource, workspace, and scopes. MCP scopes map to workspace permissions and are reevaluated on every request. |
| OAUTH-008 | OpenID Connect | OIDC is enabled separately per issuer. `sub` is pairwise, claims are minimal, and `email` requires its scope. |
| OAUTH-009 | HTTP discovery | `oauthhttp` provides RFC 8414/RFC 9728 metadata, token, revocation, and optional DCR without starting a server or imposing a consent UI. |
| OAUTH-010 | Audit and revocation | Registration, consent, issuance, rotation, denial, and revocation are auditable without logging a raw code, token, assertion, or secret. |
| OAUTH-011 | Client authentication | `private_key_jwt` accepts only ES256 or RS256 assertions with the required JWT bearer assertion type, bounded claims, public-address-pinned JWKS loading, and atomic `jti` replay protection. |
| OAUTH-012 | OIDC key rotation | The bundled ES256 signer publishes one active signing key and verification-only retiring keys; discovery advertises the actual signing algorithm and pairwise subject support. |
| OBS-001 | OTEL | Operations emit structured logs, traces, success/failure counters, and durations without high-cardinality attributes or secrets. |
| DATA-001 | PostgreSQL and SQLite | Equivalent schemas and Goose migrations are provided for both engines. |
| DATA-002 | Database access | Writes and single-record lookups are generated by sqlc; lists are traversed with `rows.Next()` and exposed through `iter.Seq2`, never materialized as slices by the repository. |
| DATA-003 | Pagination | Lists use an opaque cursor, stable ordering, and a default limit of 50. |
| DATA-004 | Lifecycle lists | Users, workspaces, memberships, OAuth issuers, resources, clients, and grants have permission-checked streamed lists. |
| ID-001 | Identifiers | All entity identifiers created by Credbound are canonical UUIDv7 values that are monotonic within a process. |
| QUAL-001 | Tests | Coverage of packages maintained by Credbound is strictly above 90%. |
| QUAL-002 | Continuous verification | CI verifies generated sources, vet, race tests, real PostgreSQL migrations/integration, maintained coverage, and reachable Go vulnerabilities. |
| OPS-001 | Operational contract | Security reporting, releases, migrations, incident revocation, privacy boundaries, and the v0 limitations of symmetric-key and pepper rotation are documented. |

### Out of scope

- IdP-specific network transport: the core provides the SSO lifecycle, linking,
  assurance, persistence, and provider port. The host service injects network
  adapters and their secrets for the providers it enables.
- Angular UI and design system: Credbound is a backend library. It exposes the
  capabilities needed by an administration interface, but every host application
  retains its presentation and first-run flow.
- H2C server, WebSocket/SSE, health checks, graceful shutdown, Docker, and
  reverse proxy: these are host-service responsibilities.
- Cookie or JWT issuance: the library returns an authenticated identity; the
  host service chooses its session strategy.
- Password reset in the first version; secondary-address verification is in scope.
- Physical deletion or automatic anonymization. Privacy erasure requires an
  application-specific, separately reviewed retention policy; Credbound exposes
  disablement and revocation primitives without deleting append-only audit facts.

## 3. Functional flows

### First account

`Bootstrap` is atomic and is possible only when the instance is empty. It
creates the user, initial workspace, `admin` membership, and instance-level
`root` role. Every subsequent call returns a conflict error.

### Instance administration

Instance roles are independent of memberships. They use the following permissions:

- `admin.access`
- `admin.audit.read`
- `admin.settings.read`, `admin.settings.write`
- `admin.users.read`, `admin.users.write`
- `admin.workspaces.read`, `admin.workspaces.write`
- `admin.rbac.read`, `admin.rbac.write`
- `admin.instance_roles.read`, `admin.instance_roles.write`

The intentionally restrictive default matrix is:

| Role | Default permissions |
|---|---|
| `root` | All permissions. |
| `developer` | Administration access, audit, and settings read/write; users, workspaces, and RBAC read. |
| `support` | Administration access, audit, users, and workspaces read; users write for support workflows authorized by the host service. |
| `marketing` | Administration access, settings, users, and workspaces read. |
| `sales` | Administration access, users, and workspaces read only. |

Applications may restrict this matrix but may never extend the authority to
modify instance roles beyond `root`.

An administration mutation calls `RequireAdminMutation`. By default, it requires
AAL2 step-up. It may accept a local request only if the server adapter constructed
`TrustedRequest{Local: true}` from an actually observed loopback connection. The
core does not interpret `Host`, `Origin`, `X-Forwarded-For`, or a client-supplied URL.

### Local authentication followed by 2FA

1. The password is verified and produces AAL1 authentication.
2. If TOTP is active, the host service does not create the final session yet.
3. A valid TOTP or recovery code promotes the context to AAL2.
4. A consumed recovery code cannot be used again.

Every successful authentication updates `User.LastSeenAt` in the same transaction
as the associated audit event.

### Email addresses

The first email address is primary and verified when the account is created
administratively. A user may request a secondary address. Credbound then returns
a raw proof once so that the host service can send it to that address; only its
HMAC is stored. An unverified address cannot be used for sign-in or made primary.

Addresses are normalized and globally unique. Changing the primary address and
removing an address are audited and protected by step-up. Removing the primary
address or the last verified address is rejected.

### Passkey

Temporary ceremony data is sealed and bound to the user, operation type, and an
expiration. Validated passkey authentication directly produces an AAL2 context.

### Step-up

`RequireStepUp` accepts only interactive AAL2 authentication whose
`AuthenticatedAt` falls within the configured window. PATs are rejected
regardless of their age.

### PAT

The raw token has the form `cbp_<prefix>_<secret>`. The prefix enables an indexed
lookup; the secret is checked in constant time against an HMAC-SHA-256. Successful
authentication updates `last_used_at` and honors expiration, revocation, the
optional workspace, and scopes.

### SSO

The host service registers zero or more `SSOProvider` implementations, each
identified by a UUIDv7 configuration and a type among `google`, `github`,
`microsoft`, `oidc`, and `saml`. Credbound seals the ceremony continuation and
persists external links.

The first link must be initiated from an existing interactive authentication.
Email addresses or names returned by the IdP are informational and never trigger
an automatic merge. A later sign-in uses the stable issuer/subject pair. A
step-up flow explicitly asks the provider to reauthenticate the user; the
validated response produces AAL2.

### SCIM

The host service creates a SCIM configuration for a workspace after AAL2 step-up
and returns the raw credential to the administrator once. It may then update the
default role and group mappings, rotate or individually revoke credentials, and
disable the configuration. Disabling it revokes all its active credentials.

An authenticated SCIM request acts as a service limited to its configuration.
`active=false` suspends only the relevant membership. Deprovisioning also revokes
the user's workspace-scoped PATs while retaining the global account and SCIM link
for auditing and possible restoration.

Roles received indirectly through groups are never accepted as free-form strings:
their target must belong to the immutable catalog registered in
`Config.WorkspaceRoles`. Instance roles remain closed and separate.

### OAuth, OpenID Connect, and MCP

The host service creates an issuer and then a protected resource for a workspace.
It may pre-register clients, accept CIMD Client Identifier URLs, or enable DCR
separately. DCR `protected` mode requires an expiring, revocable initial access
token with a registration limit; it grants no authority over a resource.

A user authorization first produces a sealed consent. After approval, the
single-use code is exchanged with PKCE for an opaque, resource-bound access token.
An optional refresh token rotates. On every request, the MCP middleware validates
the user, membership, grant, resource, and permissions corresponding to the scopes.

OIDC is invoked only if the issuer enables it and the request contains `openid`.
The ID Token is signed through the injected port and uses a pairwise subject that
does not expose the user's global UUID.

## 4. Non-functional constraints

- Every function accepts a `context.Context`.
- Email addresses are normalized (`TrimSpace`, lowercase) and unique.
- Persisted timestamps use UTC.
- User, email, workspace, passkey, SSO identity, PAT, SCIM, OAuth, and audit IDs
  are UUIDv7 values in the form `xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx`.
- Public errors are typed and never contain secrets.
- Cryptographic operations use `crypto/rand` by default and allow time/entropy
  injection only for tests.
- Infrastructure calls honor context cancellation.
- Instance roles do not implicitly grant access to workspace data: the
  administrative operation must hold the corresponding instance permission and
  remain audited.

## 5. Definition of done

- The requirements above are linked to tests.
- `go test -race ./...`, `go vet ./...`, and `make coverage` pass. Consolidated
  coverage of maintained code is strictly above 90%; sqlc code and files marked
  as generated are excluded from the calculation.
- Migrations are tested on SQLite and PostgreSQL; PostgreSQL may be marked as not
  locally verified when no server is available.
- No secret appears in logs, errors, or OTEL attributes.
