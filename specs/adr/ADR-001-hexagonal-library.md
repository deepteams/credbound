# ADR-001 — Transport-agnostic hexagonal core

- Status: accepted
- Date: 2026-08-16

## Context

Credbound must be usable by multiple Go services without imposing their HTTP
router, session model, or frontend.

## Decision

The root package contains the domain and use cases. Persistence, WebAuthn, the
clock, and entropy are ports. Adapter packages depend on the root package, never
the other way around.

The core returns typed domain errors. An HTTP adapter may translate them to RFC
9457 Problem Details, but no transport is imposed.

## Consequences

- The host service retains responsibility for cookies, CSRF, rate limiting, and
  TLS termination.
- Authorization, secret-handling, and audit invariants remain centralized.
- Applications can share the library without sharing their UI.
