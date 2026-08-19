-- +goose Up
PRAGMA foreign_keys = ON;

CREATE TABLE credbound_instance (
    singleton INTEGER PRIMARY KEY DEFAULT 1 CHECK (singleton = 1),
    initialized_at DATETIME NOT NULL
);

CREATE TABLE credbound_users (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    display_name TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    last_seen_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

-- The instance-wide user listing pages on (created_at, id); without this the
-- keyset scan degrades to a full sort of the table.
CREATE INDEX credbound_users_page_idx ON credbound_users(created_at DESC, id DESC);

CREATE TABLE credbound_user_emails (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    address TEXT NOT NULL UNIQUE,
    is_primary INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    verified_at DATETIME,
    verification_digest BLOB,
    verification_expires_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    CHECK ((verification_digest IS NULL) = (verification_expires_at IS NULL))
);
CREATE UNIQUE INDEX credbound_user_emails_primary_idx ON credbound_user_emails(user_id) WHERE is_primary = 1;
CREATE INDEX credbound_user_emails_user_order_idx ON credbound_user_emails(user_id, created_at DESC, id DESC);

CREATE TABLE credbound_password_credentials (
    user_id TEXT PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE credbound_workspaces (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    name TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX credbound_workspaces_page_idx ON credbound_workspaces(created_at DESC, id DESC);

CREATE TABLE credbound_memberships (
    workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE credbound_instance_administrators (
    user_id TEXT PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('root', 'developer', 'support', 'marketing', 'sales')),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE credbound_sso_identities (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    provider_configuration_id TEXT NOT NULL CHECK (
        length(provider_configuration_id) = 36 AND provider_configuration_id = lower(provider_configuration_id) AND
        substr(provider_configuration_id, 9, 1) = '-' AND substr(provider_configuration_id, 14, 1) = '-' AND substr(provider_configuration_id, 19, 1) = '-' AND substr(provider_configuration_id, 24, 1) = '-' AND
        length(replace(provider_configuration_id, '-', '')) = 32 AND replace(provider_configuration_id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(provider_configuration_id, 15, 1) = '7' AND substr(provider_configuration_id, 20, 1) GLOB '[89ab]'
    ),
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('google', 'github', 'microsoft', 'oidc', 'saml')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    last_used_at DATETIME,
    UNIQUE (provider_configuration_id, issuer, subject)
);
CREATE INDEX credbound_sso_identities_user_order_idx ON credbound_sso_identities(user_id, created_at DESC, id DESC);

CREATE TABLE credbound_totp_factors (
    user_id TEXT PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    encrypted_secret BLOB NOT NULL,
    active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0, 1)),
    last_used_step INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE TABLE credbound_recovery_codes (
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    digest BLOB NOT NULL,
    used_at DATETIME,
    PRIMARY KEY (user_id, digest)
);

CREATE TABLE credbound_passkeys (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id BLOB NOT NULL UNIQUE,
    credential_json BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME
);
CREATE INDEX credbound_passkeys_user_order_idx ON credbound_passkeys(user_id, created_at, id);

CREATE TABLE credbound_personal_access_tokens (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE,
    digest BLOB NOT NULL,
    workspace_id TEXT REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    scopes_json TEXT NOT NULL CHECK (json_valid(scopes_json)),
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    last_used_at DATETIME,
    revoked_at DATETIME
);
CREATE INDEX credbound_pats_user_order_idx ON credbound_personal_access_tokens(user_id, created_at DESC, id DESC);
-- Workspace-wide revocation; partial because most tokens are not scoped.
CREATE INDEX credbound_pats_workspace_idx ON credbound_personal_access_tokens(workspace_id) WHERE workspace_id IS NOT NULL;

CREATE TABLE credbound_audit_events (
    id TEXT PRIMARY KEY CHECK (
        length(id) = 36 AND id = lower(id) AND
        substr(id, 9, 1) = '-' AND substr(id, 14, 1) = '-' AND substr(id, 19, 1) = '-' AND substr(id, 24, 1) = '-' AND
        length(replace(id, '-', '')) = 32 AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*' AND
        substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]'
    ),
    occurred_at DATETIME NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    workspace_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX credbound_audit_workspace_order_idx ON credbound_audit_events(workspace_id, occurred_at DESC, id DESC);

CREATE TRIGGER credbound_audit_no_update BEFORE UPDATE ON credbound_audit_events
BEGIN SELECT RAISE(ABORT, 'credbound audit events are immutable'); END;
CREATE TRIGGER credbound_audit_no_delete BEFORE DELETE ON credbound_audit_events
BEGIN SELECT RAISE(ABORT, 'credbound audit events are immutable'); END;

-- +goose Down
DROP TRIGGER IF EXISTS credbound_audit_no_delete;
DROP TRIGGER IF EXISTS credbound_audit_no_update;
DROP TABLE IF EXISTS credbound_audit_events;
DROP TABLE IF EXISTS credbound_personal_access_tokens;
DROP TABLE IF EXISTS credbound_passkeys;
DROP TABLE IF EXISTS credbound_recovery_codes;
DROP TABLE IF EXISTS credbound_totp_factors;
DROP TABLE IF EXISTS credbound_sso_identities;
DROP TABLE IF EXISTS credbound_instance_administrators;
DROP TABLE IF EXISTS credbound_memberships;
DROP TABLE IF EXISTS credbound_workspaces;
DROP TABLE IF EXISTS credbound_password_credentials;
DROP TABLE IF EXISTS credbound_user_emails;
DROP TABLE IF EXISTS credbound_users;
DROP TABLE IF EXISTS credbound_instance;
