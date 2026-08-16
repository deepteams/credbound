-- +goose Up
ALTER TABLE credbound_workspaces ADD COLUMN disabled_at timestamptz;

-- +goose Down
ALTER TABLE credbound_workspaces DROP COLUMN disabled_at;
