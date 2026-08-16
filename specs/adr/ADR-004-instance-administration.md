# ADR-004 — Instance administration and local exception

- Status: accepted
- Date: 2026-08-16

## Context

A workspace administrator and an instance operator do not exercise the same
authority. Conflating them would let a customer become a global operator simply
by obtaining the `admin` role in a workspace.

The specifications also permit an administrative mutation without step-up on
localhost. A client can control a URL and forwarding headers unless the service
explicitly defines its trusted proxies.

## Decision

Credbound models two independent axes:

- `Role` for a workspace membership (`admin`, `member`);
- `InstanceRole` for global administration (`root`, `developer`, `support`,
  `marketing`, `sales`).

Global authorization relies on explicit `Permission` values. Only `root` can
change instance roles.

The local exception is a trust signal constructed by the server adapter from
the peer address. Credbound never derives this signal from a URL, `Host`,
`Origin`, or `X-Forwarded-For`.

## Consequences

The host service must correctly configure trusted proxies before considering a
forwarded address. The local exception removes only the AAL2 freshness
requirement; it bypasses neither authentication, administration permission, nor
auditing.
