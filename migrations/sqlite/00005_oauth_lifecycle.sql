-- +goose Up
ALTER TABLE credbound_oauth_issuers ADD COLUMN created_at DATETIME;
ALTER TABLE credbound_oauth_resources ADD COLUMN created_at DATETIME;
ALTER TABLE credbound_oauth_clients ADD COLUMN created_at DATETIME;
ALTER TABLE credbound_oauth_grants ADD COLUMN created_at DATETIME;
ALTER TABLE credbound_oauth_grants ADD COLUMN user_id TEXT REFERENCES credbound_users(id);
ALTER TABLE credbound_oauth_grants ADD COLUMN workspace_id TEXT REFERENCES credbound_workspaces(id);
UPDATE credbound_oauth_issuers SET created_at = COALESCE(json_extract(data_json, '$.CreatedAt'), CURRENT_TIMESTAMP) WHERE created_at IS NULL;
UPDATE credbound_oauth_resources SET created_at = COALESCE(json_extract(data_json, '$.CreatedAt'), CURRENT_TIMESTAMP) WHERE created_at IS NULL;
UPDATE credbound_oauth_clients SET created_at = COALESCE(json_extract(data_json, '$.CreatedAt'), CURRENT_TIMESTAMP) WHERE created_at IS NULL;
UPDATE credbound_oauth_grants SET created_at = COALESCE(json_extract(data_json, '$.CreatedAt'), CURRENT_TIMESTAMP) WHERE created_at IS NULL;
UPDATE credbound_oauth_grants SET user_id = json_extract(data_json, '$.UserID'), workspace_id = json_extract(data_json, '$.WorkspaceID') WHERE user_id IS NULL;
CREATE TRIGGER credbound_oauth_issuers_lifecycle_not_null_insert BEFORE INSERT ON credbound_oauth_issuers
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth issuer lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_issuers_lifecycle_not_null_update BEFORE UPDATE ON credbound_oauth_issuers
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth issuer lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_resources_lifecycle_not_null_insert BEFORE INSERT ON credbound_oauth_resources
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth resource lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_resources_lifecycle_not_null_update BEFORE UPDATE ON credbound_oauth_resources
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth resource lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_clients_lifecycle_not_null_insert BEFORE INSERT ON credbound_oauth_clients
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth client lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_clients_lifecycle_not_null_update BEFORE UPDATE ON credbound_oauth_clients
WHEN NEW.created_at IS NULL BEGIN SELECT RAISE(ABORT, 'OAuth client lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_grants_lifecycle_not_null_insert BEFORE INSERT ON credbound_oauth_grants
WHEN NEW.created_at IS NULL OR NEW.user_id IS NULL OR NEW.workspace_id IS NULL
BEGIN SELECT RAISE(ABORT, 'OAuth grant lifecycle columns are required'); END;
CREATE TRIGGER credbound_oauth_grants_lifecycle_not_null_update BEFORE UPDATE ON credbound_oauth_grants
WHEN NEW.created_at IS NULL OR NEW.user_id IS NULL OR NEW.workspace_id IS NULL
BEGIN SELECT RAISE(ABORT, 'OAuth grant lifecycle columns are required'); END;
CREATE INDEX credbound_oauth_issuers_page_idx ON credbound_oauth_issuers(created_at DESC, id DESC);
CREATE INDEX credbound_oauth_resources_page_idx ON credbound_oauth_resources(workspace_id, created_at DESC, id DESC);
CREATE INDEX credbound_oauth_clients_page_idx ON credbound_oauth_clients(issuer_id, created_at DESC, id DESC);
CREATE INDEX credbound_oauth_grants_page_idx ON credbound_oauth_grants(user_id, workspace_id, created_at DESC, id DESC);

-- +goose Down
DROP TRIGGER credbound_oauth_grants_lifecycle_not_null_update;
DROP TRIGGER credbound_oauth_grants_lifecycle_not_null_insert;
DROP TRIGGER credbound_oauth_clients_lifecycle_not_null_update;
DROP TRIGGER credbound_oauth_clients_lifecycle_not_null_insert;
DROP TRIGGER credbound_oauth_resources_lifecycle_not_null_update;
DROP TRIGGER credbound_oauth_resources_lifecycle_not_null_insert;
DROP TRIGGER credbound_oauth_issuers_lifecycle_not_null_update;
DROP TRIGGER credbound_oauth_issuers_lifecycle_not_null_insert;
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
