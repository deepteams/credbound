-- +goose Up
CREATE TABLE credbound_instance (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    initialized_at timestamptz NOT NULL
);

CREATE TABLE credbound_users (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    display_name text NOT NULL,
    disabled boolean NOT NULL DEFAULT false,
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound_user_emails (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    address text NOT NULL UNIQUE,
    is_primary boolean NOT NULL DEFAULT false,
    verified_at timestamptz,
    verification_digest bytea,
    verification_expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((verification_digest IS NULL) = (verification_expires_at IS NULL))
);
CREATE UNIQUE INDEX credbound_user_emails_primary_idx ON credbound_user_emails(user_id) WHERE is_primary;
CREATE INDEX credbound_user_emails_user_order_idx ON credbound_user_emails(user_id, created_at DESC, id DESC);

CREATE TABLE credbound_password_credentials (
    user_id uuid PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    hash text NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound_workspaces (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    name text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound_memberships (
    workspace_id uuid NOT NULL REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('admin', 'member')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE credbound_instance_administrators (
    user_id uuid PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('root', 'developer', 'support', 'marketing', 'sales')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound_sso_identities (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    provider_configuration_id uuid NOT NULL CHECK (substring(provider_configuration_id::text from 15 for 1) = '7' AND substring(provider_configuration_id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    provider_kind text NOT NULL CHECK (provider_kind IN ('google', 'github', 'microsoft', 'oidc', 'saml')),
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    last_used_at timestamptz,
    UNIQUE (provider_configuration_id, issuer, subject)
);
CREATE INDEX credbound_sso_identities_user_order_idx ON credbound_sso_identities(user_id, created_at DESC, id DESC);

CREATE TABLE credbound_totp_factors (
    user_id uuid PRIMARY KEY REFERENCES credbound_users(id) ON DELETE CASCADE,
    encrypted_secret bytea NOT NULL,
    active boolean NOT NULL DEFAULT false,
    last_used_step bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE credbound_recovery_codes (
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    digest bytea NOT NULL,
    used_at timestamptz,
    PRIMARY KEY (user_id, digest)
);

CREATE TABLE credbound_passkeys (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    name text NOT NULL,
    credential_id bytea NOT NULL UNIQUE,
    credential_json bytea NOT NULL,
    created_at timestamptz NOT NULL,
    last_used_at timestamptz
);
CREATE INDEX credbound_passkeys_user_order_idx ON credbound_passkeys(user_id, created_at, id);

CREATE TABLE credbound_personal_access_tokens (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    user_id uuid NOT NULL REFERENCES credbound_users(id) ON DELETE CASCADE,
    name text NOT NULL,
    prefix text NOT NULL UNIQUE,
    digest bytea NOT NULL,
    workspace_id uuid REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    scopes_json jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX credbound_pats_user_order_idx ON credbound_personal_access_tokens(user_id, created_at DESC, id DESC);

CREATE TABLE credbound_audit_events (
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
CREATE INDEX credbound_audit_workspace_order_idx ON credbound_audit_events(workspace_id, occurred_at DESC, id DESC);

CREATE FUNCTION credbound_prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'credbound audit events are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER credbound_audit_no_update BEFORE UPDATE ON credbound_audit_events
FOR EACH ROW EXECUTE FUNCTION credbound_prevent_audit_mutation();
CREATE TRIGGER credbound_audit_no_delete BEFORE DELETE ON credbound_audit_events
FOR EACH ROW EXECUTE FUNCTION credbound_prevent_audit_mutation();

-- +goose Down
DROP TRIGGER IF EXISTS credbound_audit_no_delete ON credbound_audit_events;
DROP TRIGGER IF EXISTS credbound_audit_no_update ON credbound_audit_events;
DROP FUNCTION IF EXISTS credbound_prevent_audit_mutation();
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
