# ADR-002 — Secrets, assurance levels, and step-up

- Status: accepted
- Date: 2026-08-16

## Decision

- Password: Argon2id, parameters embedded in the hash, and opportunistic rehashing.
- TOTP: secret encrypted with AES-256-GCM and a random nonce; recovery codes
  stored as HMACs.
- PAT: 256 random bits, lookup by public prefix, and constant-time HMAC comparison.
- Passkeys: WebAuthn with required user verification and a persisted signature counter.
- Step-up: fresh, interactive AAL2. A PAT never constitutes step-up.

Encryption keys and peppers are supplied by the host service and are never
stored in the database.

## Consequences

The host service must orchestrate encryption-key rotation. Losing the TOTP key
makes existing factors unusable; losing a pepper invalidates existing PATs and
recovery codes.
