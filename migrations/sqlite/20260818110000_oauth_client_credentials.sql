-- +goose Up
CREATE TABLE credbound_oauth_client_access_tokens (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), prefix TEXT NOT NULL UNIQUE, client_record_id TEXT NOT NULL REFERENCES credbound_oauth_clients(id), data_json TEXT NOT NULL);
CREATE INDEX credbound_oauth_client_access_tokens_client_idx ON credbound_oauth_client_access_tokens(client_record_id);

-- +goose Down
DROP TABLE credbound_oauth_client_access_tokens;
