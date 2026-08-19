-- +goose Up
CREATE TABLE credbound.email_issuance (address TEXT NOT NULL, purpose TEXT NOT NULL, last_issued_at timestamptz NOT NULL, PRIMARY KEY (address, purpose));

-- +goose Down
DROP TABLE credbound.email_issuance;
