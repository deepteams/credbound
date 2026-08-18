-- +goose Up
CREATE TABLE credbound.oauth_client_access_tokens (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), prefix text NOT NULL UNIQUE, client_record_id uuid NOT NULL REFERENCES credbound.oauth_clients(id), data_json jsonb NOT NULL);
CREATE INDEX oauth_client_access_tokens_client_idx ON credbound.oauth_client_access_tokens(client_record_id);

-- +goose Down
DROP TABLE credbound.oauth_client_access_tokens;
