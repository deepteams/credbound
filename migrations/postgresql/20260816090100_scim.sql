-- +goose Up
ALTER TABLE credbound.memberships DROP CONSTRAINT memberships_role_check;
ALTER TABLE credbound.memberships ADD COLUMN status text NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended'));
ALTER TABLE credbound.memberships ADD COLUMN provisioning_source text NOT NULL DEFAULT 'local';
ALTER TABLE credbound.audit_events ADD COLUMN actor_kind text NOT NULL DEFAULT 'user'
    CHECK (actor_kind IN ('user', 'service', 'system'));

CREATE TABLE credbound.scim_configurations (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    workspace_id uuid NOT NULL REFERENCES credbound.workspaces(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    default_role text NOT NULL,
    trust_directory_emails boolean NOT NULL,
    group_role_mappings_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX scim_configurations_workspace_idx ON credbound.scim_configurations(workspace_id);

CREATE TABLE credbound.scim_credentials (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    configuration_id uuid NOT NULL REFERENCES credbound.scim_configurations(id) ON DELETE CASCADE,
    prefix text NOT NULL UNIQUE,
    digest bytea NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX scim_credentials_configuration_idx ON credbound.scim_credentials(configuration_id);

CREATE TABLE credbound.scim_users (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    configuration_id uuid NOT NULL REFERENCES credbound.scim_configurations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    external_id text,
    normalized_user_name text NOT NULL,
    display_name text NOT NULL,
    emails_json jsonb NOT NULL,
    profile_json jsonb NOT NULL,
    active boolean NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deprovisioned_at timestamptz,
    UNIQUE (configuration_id, user_id),
    UNIQUE (configuration_id, normalized_user_name)
);
CREATE UNIQUE INDEX scim_users_external_id_idx ON credbound.scim_users(configuration_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX scim_users_page_idx ON credbound.scim_users(configuration_id, created_at DESC, id DESC);
-- The unique key leads on configuration_id, so anonymization and the
-- per-user link listing need their own user-scoped index.
CREATE INDEX scim_users_user_idx ON credbound.scim_users(user_id);

CREATE TABLE credbound.scim_groups (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    configuration_id uuid NOT NULL REFERENCES credbound.scim_configurations(id) ON DELETE CASCADE,
    external_id text,
    display_name text NOT NULL,
    member_ids_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz
);
CREATE UNIQUE INDEX scim_groups_external_id_idx ON credbound.scim_groups(configuration_id, external_id) WHERE external_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX scim_groups_page_idx ON credbound.scim_groups(configuration_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE IF EXISTS credbound.scim_groups;
DROP TABLE IF EXISTS credbound.scim_users;
DROP TABLE IF EXISTS credbound.scim_credentials;
DROP TABLE IF EXISTS credbound.scim_configurations;
ALTER TABLE credbound.audit_events DROP COLUMN actor_kind;
ALTER TABLE credbound.memberships DROP COLUMN provisioning_source;
ALTER TABLE credbound.memberships DROP COLUMN status;
ALTER TABLE credbound.memberships ADD CONSTRAINT memberships_role_check CHECK (role IN ('admin', 'member'));
