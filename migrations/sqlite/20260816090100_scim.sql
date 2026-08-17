-- +goose Up
ALTER TABLE credbound_memberships RENAME TO credbound_memberships_legacy;
CREATE TABLE credbound_memberships (
    workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    provisioning_source TEXT NOT NULL DEFAULT 'local',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);
INSERT INTO credbound_memberships (workspace_id, user_id, role, status, provisioning_source, created_at, updated_at)
SELECT workspace_id, user_id, role, 'active', 'local', created_at, updated_at FROM credbound_memberships_legacy;
DROP TABLE credbound_memberships_legacy;

ALTER TABLE credbound_audit_events ADD COLUMN actor_kind TEXT NOT NULL DEFAULT 'user'
    CHECK (actor_kind IN ('user', 'service', 'system'));

CREATE TABLE credbound_scim_configurations (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    default_role TEXT NOT NULL,
    trust_directory_emails INTEGER NOT NULL CHECK (trust_directory_emails IN (0, 1)),
    group_role_mappings_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);
CREATE INDEX credbound_scim_configurations_workspace_idx ON credbound_scim_configurations(workspace_id);

CREATE TABLE credbound_scim_credentials (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    configuration_id TEXT NOT NULL REFERENCES credbound_scim_configurations(id) ON DELETE CASCADE,
    prefix TEXT NOT NULL UNIQUE,
    digest BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    last_used_at DATETIME,
    revoked_at DATETIME
);
CREATE INDEX credbound_scim_credentials_configuration_idx ON credbound_scim_credentials(configuration_id);

CREATE TABLE credbound_scim_users (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    configuration_id TEXT NOT NULL REFERENCES credbound_scim_configurations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    external_id TEXT,
    normalized_user_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    emails_json TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deprovisioned_at DATETIME,
    UNIQUE (configuration_id, user_id),
    UNIQUE (configuration_id, normalized_user_name)
);
CREATE UNIQUE INDEX credbound_scim_users_external_id_idx ON credbound_scim_users(configuration_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX credbound_scim_users_page_idx ON credbound_scim_users(configuration_id, created_at DESC, id DESC);

CREATE TABLE credbound_scim_groups (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    configuration_id TEXT NOT NULL REFERENCES credbound_scim_configurations(id) ON DELETE CASCADE,
    external_id TEXT,
    display_name TEXT NOT NULL,
    member_ids_json TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    deleted_at DATETIME
);
CREATE UNIQUE INDEX credbound_scim_groups_external_id_idx ON credbound_scim_groups(configuration_id, external_id) WHERE external_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX credbound_scim_groups_page_idx ON credbound_scim_groups(configuration_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE IF EXISTS credbound_scim_groups;
DROP TABLE IF EXISTS credbound_scim_users;
DROP TABLE IF EXISTS credbound_scim_credentials;
DROP TABLE IF EXISTS credbound_scim_configurations;
-- SQLite intentionally keeps additive membership and audit columns on rollback.
