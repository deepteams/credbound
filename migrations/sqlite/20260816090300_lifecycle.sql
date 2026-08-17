-- +goose Up
ALTER TABLE credbound_workspaces ADD COLUMN disabled_at DATETIME;

-- +goose Down
ALTER TABLE credbound_workspaces DROP COLUMN disabled_at;
