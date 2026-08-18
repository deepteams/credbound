# ADR-008 — Transactional hooks and events

- Status: accepted
- Date: 2026-08-16

## Context

A service using Credbound must be able to react to authentication changes
without duplicating the library lifecycle. Two distinct needs exist:

- atomically extend a mutation with a host-service business write, such as
  allocating freemium credits when a workspace is created;
- observe a committed fact, such as sending `user.created` to Segment.

A callback executed before commit can cancel the operation but must not perform
external I/O. Conversely, a callback executed after commit may call an external
service, but its failure must not imply that the Credbound mutation failed.

## Decision

Credbound exposes two separate contracts:

- `TransactionHook` extends an open transaction and may reject it;
- `EventListener` observes a fact after commit, or a fact with no business mutation.

Transactional method names use the `Apply` prefix. They are not called “events”
because the corresponding fact has not yet been committed.

### Mutation lifecycle

A mutation follows this order:

1. validation and authorization;
2. transaction opening;
3. Credbound writes;
4. transactional hooks, in registration order;
5. append-only audit;
6. commit;
7. post-commit events, in registration order.

A transactional hook failure or panic rolls back the mutation, writes made by
earlier hooks, and the audit record. A conditional mutation that changes nothing
triggers neither a hook nor a mutation event.

A post-commit listener may return an error for observability. The emitter absorbs
the error, continues with subsequent listeners, and never returns it from the
`Manager`. There is therefore no ambiguous “mutation committed with an error”
result.

### Transaction port

The `Tx` port exposes only the store type and upcoming audit. The SQLite and
PostgreSQL adapters provide a typed `TxFrom` that gives access to the real
`*sql.Tx`. The token is valid only during the callback, cannot be retained, and
cannot be used from another goroutine.

Mutating `Store` methods receive a `Commit` envelope:

```go
type Commit struct {
    Audit         AuditEvent
    Transactional func(context.Context, Tx) error
}
```

The host service can write atomically only to tables sharing Credbound's database
and engine. An integration must support every store it enables. The in-memory
store provides a token without an external handle; shared business writes are
tested with SQLite and PostgreSQL.

### Bootstrap and workspace

`Bootstrap` triggers `ApplyUserCreate` and then `ApplyWorkspaceCreate` within its
single transaction. After commit, it emits `user.created`, `workspace.created`,
then `bootstrap.completed`.

The workspace hook is therefore immediately usable for the initial workspace
and is reused unchanged by `Manager.CreateWorkspace` (shipped with the
lifecycle surface of ADR-011), which carries its own authorization rules.

The host service retains ownership of credits, quotas, and subscriptions. It may
insert its ledger write in `ApplyWorkspaceCreate`; Credbound has no knowledge of
these concepts.

### Event identity and compatibility

Every event receives a UUIDv7 distinct from the audit UUIDv7. Names are stable
and domain-oriented: `user.created`, `workspace.created`,
`authentication.failed`, and so on.

Names and payloads carry neither a version suffix nor `schema_version`. Their
contract follows the library version and the same compatibility policy as its
Go API.

Payloads are strongly typed structs. General events never contain a password,
hash, verification or reset token, raw PAT, TOTP secret, recovery code, SSO
assertion, or SSO token.

### External delivery and outbox

A listener may call Segment after commit, using the event UUIDv7 as `messageId`.
This mode is best effort: a crash after commit or a network error can lose the
delivery.

Mandatory delivery uses an outbox owned by the host service. The outbox record
is written from the transactional hook with the same UUIDv7 as the event, then a
worker outside Credbound handles retries, idempotency, dead letters, and OTEL
observability.

Credbound implements no distributed bus, worker, or Segment client.

### Registration and observability

Hooks and listeners can be configured during construction and added at runtime.
An opaque `Subscription` allows removal without comparing interface values.
Dispatch takes a snapshot, releases its lock, and then invokes callbacks
sequentially.

Panics are recovered. Every callback produces an operation on the existing
`Observer` port without logging secrets or placing user or workspace identifiers
in OTEL attributes.

No-op interfaces are generated so that an application implements only the
callbacks it needs and a compatible addition does not break existing listeners.

## Error policy

- a Credbound sentinel returned by a hook is preserved;
- any other hook error or panic becomes `ErrTransactionRejected`;
- a post-commit error or panic is reported only to the `Observer`;
- no `ErrListenerFailed` is exposed.

## Consequences

Host services can compose atomic business writes without bringing their domain
into Credbound. Analytics integrations remain decoupled from authentication
operation results. Store adapters gain a new transactional contract, and the
`Store` interface undergoes an intentional breaking change while the library is
still in its initial version.

Hooks extend lock duration, particularly under SQLite; they must remain short,
honor the context, and never perform external I/O or invoke another `Manager`
mutation.

## Rejected alternatives

- a single interface combining transactional and post-commit phases;
- returning a post-commit error to the caller;
- an asynchronous bus inside Credbound;
- an independent version in every event;
- exposing a transaction handle as `any`;
- secrets in general events.
