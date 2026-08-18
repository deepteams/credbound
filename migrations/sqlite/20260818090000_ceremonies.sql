-- +goose Up
CREATE TABLE credbound_consumed_ceremonies (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), expires_at DATETIME NOT NULL);

-- +goose Down
DROP TABLE credbound_consumed_ceremonies;
