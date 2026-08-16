-- +goose Up
ALTER TABLE credbound_oauth_issuers ADD COLUMN created_at timestamptz;
ALTER TABLE credbound_oauth_resources ADD COLUMN created_at timestamptz;
ALTER TABLE credbound_oauth_clients ADD COLUMN created_at timestamptz;
ALTER TABLE credbound_oauth_grants ADD COLUMN created_at timestamptz;
ALTER TABLE credbound_oauth_grants ADD COLUMN user_id uuid REFERENCES credbound_users(id);
ALTER TABLE credbound_oauth_grants ADD COLUMN workspace_id uuid REFERENCES credbound_workspaces(id);
UPDATE credbound_oauth_issuers SET created_at = COALESCE((data_json->>'CreatedAt')::timestamptz, CURRENT_TIMESTAMP);
UPDATE credbound_oauth_resources SET created_at = COALESCE((data_json->>'CreatedAt')::timestamptz, CURRENT_TIMESTAMP);
UPDATE credbound_oauth_clients SET created_at = COALESCE((data_json->>'CreatedAt')::timestamptz, CURRENT_TIMESTAMP);
UPDATE credbound_oauth_grants SET created_at = COALESCE((data_json->>'CreatedAt')::timestamptz, CURRENT_TIMESTAMP);
UPDATE credbound_oauth_grants SET user_id = (data_json->>'UserID')::uuid, workspace_id = (data_json->>'WorkspaceID')::uuid;
ALTER TABLE credbound_oauth_issuers ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE credbound_oauth_resources ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE credbound_oauth_clients ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE credbound_oauth_grants ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE credbound_oauth_grants ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE credbound_oauth_grants ALTER COLUMN workspace_id SET NOT NULL;
CREATE INDEX credbound_oauth_issuers_page_idx ON credbound_oauth_issuers(created_at DESC, id DESC);
CREATE INDEX credbound_oauth_resources_page_idx ON credbound_oauth_resources(workspace_id, created_at DESC, id DESC);
CREATE INDEX credbound_oauth_clients_page_idx ON credbound_oauth_clients(issuer_id, created_at DESC, id DESC);
CREATE INDEX credbound_oauth_grants_page_idx ON credbound_oauth_grants(user_id, workspace_id, created_at DESC, id DESC);

-- +goose Down
DROP INDEX credbound_oauth_grants_page_idx;
DROP INDEX credbound_oauth_clients_page_idx;
DROP INDEX credbound_oauth_resources_page_idx;
DROP INDEX credbound_oauth_issuers_page_idx;
ALTER TABLE credbound_oauth_grants DROP COLUMN created_at;
ALTER TABLE credbound_oauth_grants DROP COLUMN workspace_id;
ALTER TABLE credbound_oauth_grants DROP COLUMN user_id;
ALTER TABLE credbound_oauth_clients DROP COLUMN created_at;
ALTER TABLE credbound_oauth_resources DROP COLUMN created_at;
ALTER TABLE credbound_oauth_issuers DROP COLUMN created_at;
