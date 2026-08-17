-- +goose Up
CREATE TABLE credbound_sessions (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), user_id TEXT NOT NULL REFERENCES credbound_users(id), method TEXT NOT NULL, level INTEGER NOT NULL, authenticated_at DATETIME NOT NULL, second_factor_required INTEGER NOT NULL DEFAULT 0, user_agent TEXT NOT NULL DEFAULT '', ip_address TEXT NOT NULL DEFAULT '', digest BLOB NOT NULL, created_at DATETIME NOT NULL, last_seen_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, revoked_at DATETIME);
CREATE INDEX credbound_sessions_user_idx ON credbound_sessions(user_id, created_at DESC, id DESC);

-- +goose Down
DROP TABLE credbound_sessions;
