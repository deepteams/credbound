# ADR-011 — Identity and workspace lifecycle

- Status: accepted
- Date: 2026-08-16

## Context

Credbound owns global users, workspaces, memberships, authentication factors,
delegated OAuth access, and their audit trail. Creating the bootstrap tenant and
granting a role is insufficient for a reusable identity library: every host
would otherwise have to reimplement suspension, removal, administrative lists,
and revocation cascades. Those implementations would drift on the security
invariants that matter most.

The host application still owns billing, product entitlements, business data,
notifications, and presentation. It may extend workspace roles and may attach
transactional hooks for credits or an outbox, but it must not have to mutate
Credbound tables directly.

## Decision

### User lifecycle

Credbound exposes instance-administrator operations to disable and re-enable a
global user. A disabled user cannot authenticate by any factor, use a PAT, use
an OAuth token, or authorize a workspace operation. Disabling a user atomically
revokes active PATs, OAuth access tokens, OAuth refresh-token families, and
active SSO sessions represented by host-owned session hooks. Stored identities,
memberships, audit records, and SCIM links are retained.

These operations require `admin.users.write` and `RequireAdminMutation`. The
last enabled `root` administrator cannot be disabled. Disabling a user is also
rejected when that user is the last enabled, active `admin` of any workspace;
the operator must first appoint another administrator so that the tenant cannot
be orphaned.

### Workspace lifecycle

An authenticated user may create a workspace after recent interactive AAL2.
The creator becomes its active local `admin`. Creation, the membership, the
transactional workspace hook, and the audit record are atomic.

Workspace administrators with `workspace.settings.write` may rename or disable
their workspace after step-up. Instance administrators with
`admin.workspaces.write` may perform the same mutation through the explicit
administrative entry point. A disabled workspace denies membership, SCIM, PAT,
and OAuth access while retaining its records for restoration and audit.

### Membership lifecycle

The public API can add an existing user, suspend or reactivate a local
membership, remove a local membership, and change its role. All mutations
require step-up plus `workspace.users.write`; role changes additionally require
`workspace.rbac.write`.

An ordinary local mutation never overwrites a SCIM-managed membership. A
workspace must always retain at least one active `admin`: suspending, removing,
or demoting the last active administrator fails atomically with `ErrConflict`.
Removing or suspending a membership atomically revokes workspace-scoped PATs,
OAuth access tokens, and OAuth refresh-token families for that user.

### Lists

Users, workspaces, memberships, OAuth issuers, resources, clients, and grants
are exposed as `iter.Seq2[PageEvent[T], error]`. They use a default page size of
50, an opaque cursor, and stable descending `(created_at, id)` ordering. Store
implementations stream SQL rows and never materialize an unbounded result.

Instance-wide user and workspace lists require the corresponding
administration read permission. A user's workspace list contains only active or
suspended memberships belonging to that user. A workspace membership list
requires `workspace.users.read`; `admin` receives this built-in permission.

### Recovery and privacy boundary

Password reset and account recovery remain outside the initial protocol
surface. They require a host-owned delivery and abuse-prevention policy. A
future implementation must use single-use, expiring HMAC credentials, perform
enumeration-resistant initiation, revoke existing authenticators according to
an explicit policy, and audit completion atomically.

Physical deletion is not exposed. A host handles a privacy request by disabling
the user, exporting or deleting its own business data, and applying a separately
reviewed anonymization policy. Credbound audit records remain append-only and
must not contain mutable profile data or secrets.

### Key and pepper rotation

The bundled OIDC adapter supports an explicit key ring with one active ES256
signing key and zero or more verification-only retiring keys. Discovery
publishes all keys in that ring. An operator keeps a retiring public key until
every ID Token signed by it has expired, while all new tokens use only the
active private key.

Version `v0` deliberately does not claim transparent overlap for `SecretKey`,
`PATPepper`, `RecoveryPepper`, or `OAuth.Pepper`: each is a single active value
in `Config`. Replacing one without preparation invalidates or makes unreadable
the credentials protected by the previous value. Rotation therefore requires
the explicit revoke, re-enrollment, or data-migration procedure in
`specs/OPERATIONS.md`. There is no default key and no silent fallback to a
retiring symmetric secret.

## Consequences

- Hosts no longer write identity tables directly for ordinary lifecycle work.
- Security-sensitive cascades and the last-administrator invariant are enforced
inside a store transaction for both SQLite and PostgreSQL.
- PostgreSQL locks the affected root-administrator set and workspace rows while
  evaluating these invariants, so concurrent demotions or disablements cannot
  both pass a stale count.
- Transaction hooks remain the integration point for billing, sessions,
  notifications, and a guaranteed-delivery outbox.
- Recovery and destructive privacy workflows cannot be enabled accidentally by
  mounting a generic endpoint.
- OIDC signing keys can overlap safely; symmetric encryption keys and peppers
  require an explicit v0 migration or credential-invalidation window.
- Custom stores must implement the lifecycle and streamed-list methods before
  claiming full Credbound v1 support.
