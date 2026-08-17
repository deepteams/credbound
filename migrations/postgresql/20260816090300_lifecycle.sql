-- +goose Up
ALTER TABLE credbound.workspaces ADD COLUMN disabled_at timestamptz;

-- +goose Down
ALTER TABLE credbound.workspaces DROP COLUMN disabled_at;
