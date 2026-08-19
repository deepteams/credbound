-- +goose Up
CREATE TABLE credbound.workspace_domains (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), workspace_id uuid NOT NULL REFERENCES credbound.workspaces(id), domain text NOT NULL UNIQUE, challenge text NOT NULL, confirmed_at timestamptz, auto_join boolean NOT NULL DEFAULT false, auto_join_role text NOT NULL DEFAULT '', sso_provider_configuration_id uuid, enforce_sso boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL);
CREATE INDEX workspace_domains_workspace_idx ON credbound.workspace_domains(workspace_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE credbound.workspace_domains;
