-- +goose Up
CREATE TABLE credbound.oauth_issuers (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    issuer text NOT NULL UNIQUE,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_resources (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    issuer_id uuid NOT NULL REFERENCES credbound.oauth_issuers(id) ON DELETE CASCADE,
    workspace_id uuid NOT NULL REFERENCES credbound.workspaces(id) ON DELETE CASCADE,
    resource text NOT NULL UNIQUE,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_clients (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    issuer_id uuid NOT NULL REFERENCES credbound.oauth_issuers(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    data_json jsonb NOT NULL,
    UNIQUE (issuer_id, client_id)
);
CREATE TABLE credbound.oauth_initial_access_tokens (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    issuer_id uuid NOT NULL REFERENCES credbound.oauth_issuers(id) ON DELETE CASCADE,
    prefix text NOT NULL UNIQUE,
    registration_count integer NOT NULL,
    max_registrations integer NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_grants (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    client_record_id uuid NOT NULL REFERENCES credbound.oauth_clients(id) ON DELETE CASCADE,
    resource_id uuid NOT NULL REFERENCES credbound.oauth_resources(id) ON DELETE CASCADE,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_authorization_codes (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    prefix text NOT NULL UNIQUE,
    grant_id uuid NOT NULL REFERENCES credbound.oauth_grants(id) ON DELETE CASCADE,
    used_at timestamptz,
    expires_at timestamptz NOT NULL,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_access_tokens (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    prefix text NOT NULL UNIQUE,
    grant_id uuid NOT NULL REFERENCES credbound.oauth_grants(id) ON DELETE CASCADE,
    data_json jsonb NOT NULL
);
CREATE TABLE credbound.oauth_refresh_tokens (
    id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    family_id uuid NOT NULL CHECK (substring(family_id::text from 15 for 1) = '7' AND substring(family_id::text from 20 for 1) IN ('8', '9', 'a', 'b')),
    prefix text NOT NULL UNIQUE,
    grant_id uuid NOT NULL REFERENCES credbound.oauth_grants(id) ON DELETE CASCADE,
    used_at timestamptz,
    revoked_at timestamptz,
    expires_at timestamptz NOT NULL,
    data_json jsonb NOT NULL
);
CREATE INDEX oauth_refresh_family_idx ON credbound.oauth_refresh_tokens(family_id);
-- Revoking a grant cascades to its tokens, and deleting a client or a
-- resource cascades to its grants; each cascade filters on the foreign key.
CREATE INDEX oauth_access_tokens_grant_idx ON credbound.oauth_access_tokens(grant_id);
CREATE INDEX oauth_refresh_grant_idx ON credbound.oauth_refresh_tokens(grant_id);
CREATE INDEX oauth_grants_client_idx ON credbound.oauth_grants(client_record_id);
CREATE INDEX oauth_grants_resource_idx ON credbound.oauth_grants(resource_id);
-- Open dynamic client registration counts an issuer's tokens on every call.
CREATE INDEX oauth_initial_access_tokens_issuer_idx ON credbound.oauth_initial_access_tokens(issuer_id);

-- +goose Down
DROP TABLE IF EXISTS credbound.oauth_refresh_tokens;
DROP TABLE IF EXISTS credbound.oauth_access_tokens;
DROP TABLE IF EXISTS credbound.oauth_authorization_codes;
DROP TABLE IF EXISTS credbound.oauth_grants;
DROP TABLE IF EXISTS credbound.oauth_initial_access_tokens;
DROP TABLE IF EXISTS credbound.oauth_clients;
DROP TABLE IF EXISTS credbound.oauth_resources;
DROP TABLE IF EXISTS credbound.oauth_issuers;
