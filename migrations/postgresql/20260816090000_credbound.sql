-- +goose Up
CREATE SCHEMA credbound;

CREATE TABLE credbound.instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    initialized_at timestamptz NOT NULL
);

CREATE TABLE credbound.users (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    display_name text NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

-- The instance-wide user listing pages on (created_at, id); without this the
-- keyset scan degrades to a full sort of the table.
CREATE INDEX users_page_idx ON credbound.users(created_at DESC, id DESC);

CREATE TABLE credbound.user_emails (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    address text NOT NULL UNIQUE,
    is_primary boolean NOT NULL DEFAULT false,
    verified_at timestamptz,
    verification_digest bytea,
    verification_expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((verification_digest IS NULL) = (verification_expires_at IS NULL))
);
CREATE UNIQUE INDEX user_emails_primary_idx ON credbound.user_emails(user_id) WHERE is_primary;
CREATE INDEX user_emails_user_order_idx ON credbound.user_emails(user_id, created_at DESC, id DESC);

CREATE TABLE credbound.password_credentials (
    user_id uuid PRIMARY KEY REFERENCES credbound.users(id) ON DELETE CASCADE,
    hash text NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound.workspaces (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX workspaces_page_idx ON credbound.workspaces(created_at DESC, id DESC);

CREATE TABLE credbound.memberships (
    workspace_id uuid NOT NULL REFERENCES credbound.workspaces(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);

-- The primary key leads on workspace_id, so the user-scoped lookups (the
-- sole-admin and orphaned-workspace guards, and the workspace listing's
-- EXISTS) have nothing to search on without this.
CREATE INDEX memberships_user_idx ON credbound.memberships(user_id);

CREATE TABLE credbound.instance_administrators (
    user_id uuid PRIMARY KEY REFERENCES credbound.users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('root', 'developer', 'support', 'marketing', 'sales')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound.sso_identities (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    provider_configuration_id uuid NOT NULL CHECK (substring(provider_configuration_id::text from 15 for 1) = '7' AND substring(provider_configuration_id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    provider_kind text NOT NULL CHECK (provider_kind IN ('google', 'github', 'microsoft', 'oidc', 'saml')),
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    UNIQUE (provider_configuration_id, issuer, subject)
);
CREATE INDEX sso_identities_user_order_idx ON credbound.sso_identities(user_id, created_at DESC, id DESC);

CREATE TABLE credbound.totp_factors (
    user_id uuid PRIMARY KEY REFERENCES credbound.users(id) ON DELETE CASCADE,
    encrypted_secret bytea NOT NULL,
    active boolean NOT NULL DEFAULT false,
    last_used_step bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound.recovery_codes (
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    digest bytea NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (user_id, digest)
);

CREATE TABLE credbound.passkeys (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    name text NOT NULL,
    credential_id bytea NOT NULL UNIQUE,
    credential_json bytea NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz
);
CREATE INDEX passkeys_user_order_idx ON credbound.passkeys(user_id, created_at, id);

CREATE TABLE credbound.personal_access_tokens (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound.users(id) ON DELETE CASCADE,
    name text NOT NULL,
    prefix text NOT NULL UNIQUE,
    digest bytea NOT NULL,
    workspace_id uuid REFERENCES credbound.workspaces(id) ON DELETE CASCADE,
    scopes_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX pats_user_order_idx ON credbound.personal_access_tokens(user_id, created_at DESC, id DESC);
-- Workspace-wide revocation; partial because most tokens are not scoped.
CREATE INDEX pats_workspace_idx ON credbound.personal_access_tokens(workspace_id) WHERE workspace_id IS NOT NULL;

CREATE TABLE credbound.audit_events (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    occurred_at timestamptz NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    workspace_id uuid,
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    reason text NOT NULL DEFAULT ''
);
CREATE INDEX audit_workspace_order_idx ON credbound.audit_events(workspace_id, occurred_at DESC, id DESC);

CREATE FUNCTION credbound.prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'credbound audit events are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_no_update BEFORE UPDATE ON credbound.audit_events
FOR EACH ROW EXECUTE FUNCTION credbound.prevent_audit_mutation();
CREATE TRIGGER audit_no_delete BEFORE DELETE ON credbound.audit_events
FOR EACH ROW EXECUTE FUNCTION credbound.prevent_audit_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS audit_no_delete ON credbound.audit_events;
DROP TRIGGER IF EXISTS audit_no_update ON credbound.audit_events;
DROP FUNCTION IF EXISTS credbound.prevent_audit_mutation();
DROP TABLE IF EXISTS credbound.audit_events;
DROP TABLE IF EXISTS credbound.personal_access_tokens;
DROP TABLE IF EXISTS credbound.passkeys;
DROP TABLE IF EXISTS credbound.recovery_codes;
DROP TABLE IF EXISTS credbound.totp_factors;
DROP TABLE IF EXISTS credbound.sso_identities;
DROP TABLE IF EXISTS credbound.instance_administrators;
DROP TABLE IF EXISTS credbound.memberships;
DROP TABLE IF EXISTS credbound.workspaces;
DROP TABLE IF EXISTS credbound.password_credentials;
DROP TABLE IF EXISTS credbound.user_emails;
DROP TABLE IF EXISTS credbound.users;
DROP TABLE IF EXISTS credbound.instance;
DROP SCHEMA credbound;
