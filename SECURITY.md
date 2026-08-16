# Security policy

## Supported versions

Credbound is currently released as `v0`. Security fixes are applied to the
latest tagged `v0` release and the default branch. Older pre-1.0 releases may
not receive backports.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory reporting flow for this repository, or contact the Deepteams
maintainers through the private security channel listed in the repository
organization profile.

Include the affected version or commit, the relevant configuration and store,
reproduction steps, impact, and any suggested mitigation. Never include live
passwords, tokens, private keys, peppers, personal data, or production database
dumps. Use synthetic values and redact logs before attaching them.

The maintainers will acknowledge a complete report, reproduce it in a private
environment, coordinate a fix and disclosure, and credit the reporter when
requested. Please allow time for users to update before publishing details.

## Security boundary

Credbound owns authentication, authorization, credential persistence,
revocation, and audit invariants. A host service still owns TLS, trusted-proxy
configuration, cookies and sessions, CSRF, request and rate limits, login and
consent UI, secret storage, backups, and incident response. See
[`specs/OPERATIONS.md`](specs/OPERATIONS.md) before a production deployment.
