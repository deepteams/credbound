# ADR-009 — Workspace-scoped SCIM provisioning

- Status: accepted
- Date: 2026-08-16

## Context

Credbound already manages global users, their email addresses, workspaces,
memberships, RBAC, SSO, and auditing. Applications offering an enterprise plan
must also let a directory such as Microsoft Entra ID, Okta, or Google Workspace
provision and deprovision users without reproducing this lifecycle in every SaaS
application.

SCIM 2.0 defines a common schema for `User` and `Group` resources and an HTTP
protocol for creation, retrieval, replacement, patching, and deletion:

- [RFC 7643 — Core Schema](https://datatracker.ietf.org/doc/html/rfc7643);
- [RFC 7644 — Protocol](https://datatracker.ietf.org/doc/html/rfc7644);
- [RFC 9865 — Cursor-Based Pagination](https://datatracker.ietf.org/doc/html/rfc9865).

SCIM is a provisioning protocol, not an authentication method. SSO proves
identity during sign-in; SCIM prepares and maintains accounts, memberships, and
groups before sign-in.

The Credbound model also imposes two structural constraints:

- a `User` is global and may belong to multiple workspaces;
- `admin` and `member` are the immutable baseline roles, while applications may
  register roles such as `viewer`, `editor`, `manager`, or domain-specific
  roles in the manager's frozen workspace catalog.

A SCIM implementation must therefore neither disable a user globally from a
single workspace nor accept an arbitrary role string supplied by a directory.

## Decision

Credbound provides an optional SCIM 2.0 module isolated by workspace. It has two
layers:

- the core contains the model, transactional mutations, RBAC, auditing, hooks,
  and events;
- an optional `scimhttp` adapter implements the SCIM HTTP protocol and can be
  mounted by the host service under `/scim/v2`.

Credbound remains a library and starts no HTTP server.

### Provisioning domain

Every `SCIMConfiguration` belongs to exactly one workspace and has a UUIDv7.
The configuration forms the provisioning domain in SCIM terms. It contains at
least:

- `ID`;
- `WorkspaceID`;
- `Enabled`;
- the default role;
- group-to-role mappings;
- the explicit policy for trusting directory email addresses;
- creation and modification timestamps.

A workspace may have multiple SCIM configurations, for example during a
directory migration. Identities and `externalId` values remain strictly scoped
to their configuration.

Creating or modifying a configuration requires a workspace administrator with
fresh AAL2 step-up. The host service may add a commercial permission or plan
check before enabling this capability.

### SCIM identifier and local link

A SCIM resource does not directly expose the global `User.ID`. Credbound
persists a `SCIMUserLink` containing:

- a UUIDv7 `ID` used as the SCIM resource `id`;
- `ConfigurationID`;
- `UserID`;
- the `ExternalID` supplied by the provisioning client;
- normalized `UserName`;
- provisioning state and its timestamps.

This indirection avoids giving multiple organizations that reference the same
global user a shared, correlatable identifier. `SCIMUserLink.ID` is stable,
non-reassignable, and unique within the service. The
`(configuration_id, external_id)` pair is unique when an `externalId` is
provided. The `(configuration_id, normalized_user_name)` pair is also unique.

Every SCIM lookup and constraint includes the configuration and workspace.
Possessing an identifier or cursor from another workspace grants no access.

### Membership lifecycle

A membership receives an explicit state:

- `active`: the user may be authorized in the workspace;
- `suspended`: workspace access is denied, but the link and history are retained.

`SCIM User.active=false` suspends only the membership managed by the relevant
configuration. It never sets `User.Disabled`, because that field disables the
account across the entire instance. `active=true` reactivates the membership if
the configuration is still authorized to manage it.

`DELETE /Users/{id}` performs logical, idempotent deprovisioning: the membership
is suspended and the active resource is no longer returned, but its stable link
is retained for auditing and possible reprovisioning. PATs bound to that
workspace are revoked in the same transaction. The host service receives an
event so it can invalidate its sessions and application permissions.

Every membership has exactly one provisioning source: `local` or the ID of a
SCIM configuration. A SCIM configuration may change, suspend, or assign a role
only to memberships for which it is the source. Encountering a local membership
or one managed by another configuration returns a conflict. Adoption or source
transfer requires an explicit administrative operation that is audited and
protected by step-up. This rule also makes migration between two directories
deterministic.

Locally changing the role of a SCIM-managed membership requires an explicit
takeover operation that replaces its source with `local`. An ordinary RBAC
mutation never silently bypasses the source-of-truth directory.

### User creation and matching

The core adds a provisioning primitive capable of creating a user without a
local password. No fake or unusable password is generated. Later local
authentication goes through an explicit password activation or definition flow.

Email addresses used as Credbound identifiers remain normalized and globally
unique. When the primary email of a SCIM creation already belongs to another
user, Credbound returns a conflict and performs no automatic merge. Attaching to
an existing user requires an explicit administrative operation that is audited
and protected by step-up.

SCIM does not automatically create an SSO link by email. Automatic correlation
with `issuer` and `subject` is possible only if a future explicit contract links
the SCIM configuration to the SSO provider and defines a shared stable
identifier. Email alone is never proof of a link.

The SCIM `password` attribute is not supported in the first version.
`changePassword.supported` is advertised as `false`, the value is never logged
or persisted, and an attempt to use it returns an appropriate SCIM error.

Profile attributes received through SCIM are retained on the tenant-scoped
link. When a new user is created, the primary SCIM email becomes their global
primary email. Other SCIM email addresses remain tenant-scoped profile
attributes: they do not become sign-in identifiers and do not modify addresses
already owned by the global account. The primary address remains unverified by
default; it is marked verified only when a workspace administrator explicitly
enables a policy that trusts directory email addresses. This trust still does
not permit automatic merging.

### Extensible workspace roles

`admin` and `member` are the minimum built-in roles, not the definitive list of
application roles. This decision extends the workspace portion of
[ADR-004](ADR-004-instance-administration.md) without changing instance-
administration roles.

When constructing the `Manager`, the host service may register additional role
definitions. A definition contains:

- a stable name of type `Role`;
- the granted workspace permissions;
- any roles from which it inherits.

Permission-based authorization becomes the canonical contract through an
operation such as `AuthorizePermission(ctx, authn, workspaceID, permission)`.
Hard-coded rank comparison is removed. `admin` automatically receives every
registered workspace permission, including application permissions, while
`member` retains minimum access. The application may add permissions to the
built-in roles but cannot remove those roles or their Credbound-provided
guarantees.

Applications may also declare their own workspace permissions and associate
them with their roles. Credbound validates names, rejects inheritance cycles and
unknown roles, and constructs a catalog that is immutable for the lifetime of
the `Manager`. A persisted role string absent from the catalog fails closed
during authorization.

The `root`, `developer`, `support`, `marketing`, and `sales` instance roles
remain a separate axis. Extending workspace roles cannot grant any instance-
administration permission.

### SCIM groups and role mapping

Credbound supports SCIM `Group` resources and persists their memberships. A
SCIM group is not automatically a Credbound role. The configuration contains
explicit mappings:

```text
external group A -> editor
external group B -> admin
no mapped group -> member
```

A mapping target must be a role in the `Manager` catalog. SCIM can never create
a role or introduce an arbitrary role name.

Updating the default role or mappings recomputes every active SCIM membership
for the configuration in the same transaction as the configuration and its
audit. An ambiguity cancels the entire update.

When a user belongs to multiple groups mapped to different roles, an explicit
mapping priority determines the selected role. Two applicable mappings at the
same priority form an ambiguous configuration, and the mutation fails closed.
Nested groups are not supported in the first version.

A group update and the resulting membership or role changes are applied in one
transaction with their audit.

### SCIM client authentication

A configuration has one or more rotating service credentials. Every secret has
at least 256 bits of entropy, is returned in plaintext only once, and only an
HMAC digest is persisted. Credentials have their own UUIDv7, expiration date,
revocation date, and `last_used_at`.

A SCIM credential:

- is limited to its configuration and workspace;
- does not represent a user;
- cannot satisfy application authentication, a PAT, step-up, or an instance-
  administration permission;
- is subject to host-service rate limiting.

Auditing distinguishes `user` and `service` actors. A SCIM mutation uses the
credential or configuration as its service actor without impersonating a human
user.

A workspace administrator with step-up may revoke a specific credential.
Disabling the configuration atomically revokes all its still-active credentials.
An expired or revoked secret, or one attached to a disabled configuration,
produces the same public error as an unknown secret.

### SCIM HTTP contract

The first version of `scimhttp` exposes:

- `/ServiceProviderConfig`;
- `/ResourceTypes`;
- `/Schemas`;
- `/Users`, `/Users/{id}`, and `/Users/.search`;
- `/Groups`, `/Groups/{id}`, and `/Groups/.search`.

Supported operations are `GET`, `POST`, `PUT`, `PATCH`, and `DELETE`. The
capabilities actually available are advertised in `ServiceProviderConfig`. Bulk
is advertised as unsupported in the first version.

Initial filters cover at least `id`, `externalId`, `userName`, `emails.value`,
and `active`. An unsupported filter or PATCH path returns an explicit SCIM error
and is never silently ignored.

Native pagination uses RFC 9865 opaque cursors, with a default page size of 50
and stable ordering. An indexed compatibility profile may be added for a
provider that does not yet support cursors, without introducing offsets into
the core repository port.

Responses use `application/scim+json` and the SCIM error schema. They are a
protocol-specific exception to RFC 9457. SCIM `ListResponse` values are JSON
objects containing `Resources`; the adapter progressively encodes them from
`iter.Seq2` without materializing the resources in a slice.

### Atomicity, audit, and events

Every SCIM mutation follows the ADR-008 lifecycle:

1. service credential authentication;
2. configuration and workspace resolution;
3. SCIM and RBAC validation;
4. Credbound mutation;
5. corresponding host-service transactional hooks, when present;
6. append-only audit;
7. commit;
8. post-commit events.

Minimum events are:

- `scim.user.provisioned`;
- `scim.user.updated`;
- `scim.user.activated`;
- `scim.user.suspended`;
- `scim.user.deprovisioned`;
- `scim.group.created`;
- `scim.group.updated`;
- `scim.group.deleted`;
- `scim.group.members_changed`.

Corresponding transactional hooks let the host service update licenses, quotas,
application groups, or an outbox within the same transaction. Payloads never
contain a SCIM credential, password, SSO token, or other secret.

### Persistence and observability

Goose migrations and sqlc queries are provided for SQLite and PostgreSQL. Lists
use `rows.Next()` with timeouts, backpressure, and stable pagination. All
identifiers created by Credbound are UUIDv7 values.

Every operation and callback is observed through OTEL without secrets, email
addresses, `externalId`, user identifiers, or workspace identifiers in high-
cardinality attributes.

## Initially out of scope

- creating or deleting workspaces through a custom SCIM resource;
- outbound synchronization in which Credbound acts as a SCIM client;
- nested groups;
- the SCIM Bulk endpoint;
- password change or reset through SCIM;
- automatic account merging by email;
- automatic SSO linking without an explicitly configured stable identifier;
- host-service session management.

## Consequences

SCIM becomes a capability enabled per application and workspace without
expanding the trust surface of every SaaS application that uses Credbound. The
global user model remains compatible with multiple workspaces because
deprovisioning applies to the membership rather than the global account.

Workspace RBAC becomes genuinely extensible. This change breaks the current API
based on `normalizeRole` and `roleRank`; the break is accepted before the first
stable version. Applications must register their roles before constructing the
`Manager` and cannot modify the catalog at runtime.

The implementation includes user and membership lifecycle primitives, the role
catalog, the SCIM domain, in-memory/SQLite/PostgreSQL stores, and the HTTP
adapter. Maintained-code coverage remains strictly above 90%. PostgreSQL
migrations must also be validated against a real instance in a consuming
project's CI.

## Rejected alternatives

- treating SCIM as an SSO variant;
- exposing the global `User.ID` as the SCIM identifier in every workspace;
- applying `active=false` to `User.Disabled`;
- automatically merging accounts by email;
- accepting the role sent by the SCIM client without a local catalog;
- hard-coding every application role in Credbound;
- systematically translating SCIM groups into roles of the same name;
- buffering an entire `ListResponse` before sending it;
- starting an HTTP server from the library.
