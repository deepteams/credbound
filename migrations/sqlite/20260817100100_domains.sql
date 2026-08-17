-- +goose Up
CREATE TABLE credbound_workspace_domains (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id), domain TEXT NOT NULL UNIQUE, challenge TEXT NOT NULL, confirmed_at DATETIME, auto_join INTEGER NOT NULL DEFAULT 0, auto_join_role TEXT NOT NULL DEFAULT '', sso_provider_configuration_id TEXT NOT NULL DEFAULT '', enforce_sso INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL);
CREATE INDEX credbound_workspace_domains_workspace_idx ON credbound_workspace_domains(workspace_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE credbound_workspace_domains;
