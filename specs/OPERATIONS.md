# Operations guide

Credbound is a library. These requirements apply to each host service that
mounts its handlers or calls its manager.

## Startup and secrets

Provide independent, randomly generated production values through a secret
manager:

| Value | Minimum | Protects | v0 rotation effect |
|---|---:|---|---|
| `SecretKey` | exactly 32 bytes | TOTP secrets and sealed continuations | Existing TOTP factors cannot be decrypted after an un-migrated replacement. In-flight continuations fail closed. |
| `PATPepper` | 32 bytes | PAT HMACs | Existing PATs become invalid. |
| `RecoveryPepper` | 32 bytes | TOTP recovery-code HMACs | Existing recovery codes become invalid. |
| `OAuth.Pepper` | 32 bytes | OAuth codes, secrets, tokens, and pairwise OIDC subjects | Existing OAuth credentials become invalid and pairwise subjects change. |

Never reuse a value across purposes, persist it in the application database,
pass it on a command line, or emit it to logs and telemetry. Startup must fail
when a required value is absent or malformed.

## Rotation

`SecretKey`, PAT, recovery, and OAuth peppers are single active values in v0;
there is no transparent symmetric key ring. Plan their rotation as a credential
invalidation or explicit data-migration event:

1. announce the affected sign-in or API interruption;
2. revoke affected PATs, OAuth grants/tokens, and recovery codes as applicable;
3. migrate encrypted TOTP material with a separately reviewed tool or require
   TOTP re-enrollment before replacing `SecretKey`;
4. wait at least the configured ceremony lifetime before removing the old key
   if only sealed continuations are affected;
5. deploy the new secret and monitor authentication and audit failures;
6. destroy retired symmetric material only after rollback is no longer needed.

OIDC signing rotation is different. Construct `oidcadapter.NewES256KeyRing`
with the new active private key and the old public key as a retiring
verification key. Keep the retiring key in JWKS until every ID Token it signed
has expired, then deploy a ring without it. KIDs must be unique and stable.

## Database migrations and recovery

Apply the embedded Goose migrations in filename order before serving traffic.
Do not edit a migration that has shipped. PostgreSQL and SQLite must enable
their documented foreign-key behavior. Back up the database and secret-manager
references together; a database backup without its encryption key cannot
restore TOTP authentication.

Test restoration on an isolated environment. Audit tables are append-only:
recovery tooling must not rewrite or delete audit rows. Transaction-hook writes
must use the provided bounded transaction capability so application outbox,
billing, or credit changes commit atomically with the Credbound mutation.

## OAuth, CIMD, and DCR

- Configure canonical issuer and resource URLs; never infer them from request
  `Host` or forwarding headers.
- Terminate TLS at a trusted edge and allow only the proxy headers that edge
  overwrites.
- Apply distributed rate limits to authorization, token, registration,
  UserInfo, and CIMD traffic. The bundled CIMD fetcher provides process-local
  concurrency and network-safety limits, not distributed abuse prevention.
- Prefer CIMD with DCR disabled for unknown MCP clients. Use protected DCR when
  compatibility requires registration. Open DCR is an explicit high-risk mode.
- Protected DCR capacity is bounded by each initial access token. Open DCR
  capacity is the issuer's active-client limit. Review and disable unused DCR
  clients to release capacity; v0 performs no automatic client deletion.
- Mount `oauthhttp.Protect` on every protected MCP route and specify the minimum
  scope for that operation.

## Incident actions

- Compromised user: disable the user. Credbound revokes PAT and OAuth access
  paths while retaining identity and audit records.
- Compromised workspace: disable the workspace, then review memberships, SCIM
  credentials, OAuth grants, hooks, and application sessions.
- Compromised PAT or OAuth grant: revoke the individual PAT, token, or grant.
- Compromised OAuth client: disable the client and rotate any client key or
  secret before re-enabling it.
- Compromised issuer signing key: activate a new key immediately. Retain the old
  public key only when doing so is safe; otherwise remove it and accept that
  outstanding ID Tokens will fail validation.
- Compromised symmetric key or pepper: follow the invalidation procedure above
  and rotate host sessions and downstream credentials independently.

## Recovery and privacy

Password reset and destructive account deletion are not generic v0 endpoints.
The host must design enumeration-resistant delivery, abuse controls, identity
proofing, session revocation, and audit policy before adding recovery.

For a privacy request, disable the user first, export or erase application-owned
business data according to the host retention policy, and review any proposed
identity anonymization separately. Credbound audit facts remain append-only and
must contain identifiers and outcomes rather than secrets or mutable profile
snapshots.

## Observability

Alert on repeated authentication failures, refresh-token reuse, audit write
failure, SCIM credential rejection, CIMD rejection, DCR quota exhaustion, and
unexpected disabled-resource access. Do not attach raw email proofs, passwords,
TOTP values, assertions, codes, access/refresh tokens, client secrets, private
keys, or peppers to logs, traces, metrics, events, or error messages.
