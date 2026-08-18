-- +goose Up
CREATE TABLE credbound_email_issuance (address TEXT NOT NULL, purpose TEXT NOT NULL, last_issued_at DATETIME NOT NULL, PRIMARY KEY (address, purpose));

-- +goose Down
DROP TABLE credbound_email_issuance;
