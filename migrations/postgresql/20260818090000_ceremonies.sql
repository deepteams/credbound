-- +goose Up
CREATE TABLE credbound.consumed_ceremonies (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), expires_at timestamptz NOT NULL);

-- +goose Down
DROP TABLE credbound.consumed_ceremonies;
