-- +goose Up
CREATE TABLE credbound.sessions (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), user_id uuid NOT NULL REFERENCES credbound.users(id), method text NOT NULL, level smallint NOT NULL, authenticated_at timestamptz NOT NULL, second_factor_required boolean NOT NULL DEFAULT false, user_agent text NOT NULL DEFAULT '', ip_address text NOT NULL DEFAULT '', digest bytea NOT NULL, created_at timestamptz NOT NULL, last_seen_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz);
CREATE INDEX sessions_user_idx ON credbound.sessions(user_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE credbound.sessions;
