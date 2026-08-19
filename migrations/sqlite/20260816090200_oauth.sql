-- +goose Up
CREATE TABLE credbound_oauth_issuers (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    issuer TEXT NOT NULL UNIQUE,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_resources (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    issuer_id TEXT NOT NULL REFERENCES credbound_oauth_issuers(id) ON DELETE CASCADE,
    workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id) ON DELETE CASCADE,
    resource TEXT NOT NULL UNIQUE,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_clients (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    issuer_id TEXT NOT NULL REFERENCES credbound_oauth_issuers(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    data_json TEXT NOT NULL,
    UNIQUE (issuer_id, client_id)
);
CREATE TABLE credbound_oauth_initial_access_tokens (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    issuer_id TEXT NOT NULL REFERENCES credbound_oauth_issuers(id) ON DELETE CASCADE,
    prefix TEXT NOT NULL UNIQUE,
    registration_count INTEGER NOT NULL,
    max_registrations INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_grants (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    client_record_id TEXT NOT NULL REFERENCES credbound_oauth_clients(id) ON DELETE CASCADE,
    resource_id TEXT NOT NULL REFERENCES credbound_oauth_resources(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_authorization_codes (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    prefix TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES credbound_oauth_grants(id) ON DELETE CASCADE,
    used_at DATETIME,
    expires_at DATETIME NOT NULL,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_access_tokens (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    prefix TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES credbound_oauth_grants(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL
);
CREATE TABLE credbound_oauth_refresh_tokens (
    id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    family_id TEXT NOT NULL CHECK (length(family_id) = 36 AND family_id = lower(family_id) AND substr(family_id, 15, 1) = '7' AND substr(family_id, 20, 1) GLOB '[89ab]' AND replace(family_id, '-', '') NOT GLOB '*[^0-9a-f]*'),
    prefix TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL REFERENCES credbound_oauth_grants(id) ON DELETE CASCADE,
    used_at DATETIME,
    revoked_at DATETIME,
    expires_at DATETIME NOT NULL,
    data_json TEXT NOT NULL
);
CREATE INDEX credbound_oauth_refresh_family_idx ON credbound_oauth_refresh_tokens(family_id);
-- Revoking a grant cascades to its tokens, and deleting a client or a
-- resource cascades to its grants; each cascade filters on the foreign key.
CREATE INDEX credbound_oauth_access_tokens_grant_idx ON credbound_oauth_access_tokens(grant_id);
CREATE INDEX credbound_oauth_refresh_grant_idx ON credbound_oauth_refresh_tokens(grant_id);
CREATE INDEX credbound_oauth_grants_client_idx ON credbound_oauth_grants(client_record_id);
CREATE INDEX credbound_oauth_grants_resource_idx ON credbound_oauth_grants(resource_id);
-- Open dynamic client registration counts an issuer's tokens on every call.
CREATE INDEX credbound_oauth_initial_access_tokens_issuer_idx ON credbound_oauth_initial_access_tokens(issuer_id);

-- +goose Down
DROP TABLE IF EXISTS credbound_oauth_refresh_tokens;
DROP TABLE IF EXISTS credbound_oauth_access_tokens;
DROP TABLE IF EXISTS credbound_oauth_authorization_codes;
DROP TABLE IF EXISTS credbound_oauth_grants;
DROP TABLE IF EXISTS credbound_oauth_initial_access_tokens;
DROP TABLE IF EXISTS credbound_oauth_clients;
DROP TABLE IF EXISTS credbound_oauth_resources;
DROP TABLE IF EXISTS credbound_oauth_issuers;
