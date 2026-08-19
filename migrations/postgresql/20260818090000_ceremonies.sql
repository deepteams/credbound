-- +goose Up
CREATE TABLE credbound.consumed_ceremonies (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), expires_at timestamptz NOT NULL);

-- Every ceremony-bearing mutation prunes expired rows before inserting.
CREATE INDEX consumed_ceremonies_expiry_idx ON credbound.consumed_ceremonies(expires_at);

-- +goose Down
DROP TABLE credbound.consumed_ceremonies;
