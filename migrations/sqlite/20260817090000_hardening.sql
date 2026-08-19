-- +goose Up
ALTER TABLE credbound_workspaces ADD COLUMN require_mfa INTEGER NOT NULL DEFAULT 0;
ALTER TABLE credbound_audit_events ADD COLUMN ip_address TEXT NOT NULL DEFAULT '';
ALTER TABLE credbound_audit_events ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE credbound_audit_events ADD COLUMN sequence INTEGER;
ALTER TABLE credbound_audit_events ADD COLUMN previous_hash BLOB;
ALTER TABLE credbound_audit_events ADD COLUMN hash BLOB;
CREATE UNIQUE INDEX credbound_audit_events_sequence_idx ON credbound_audit_events(sequence) WHERE sequence IS NOT NULL;
CREATE TABLE credbound_audit_chain (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), sequence INTEGER NOT NULL, head_hash BLOB NOT NULL);
INSERT INTO credbound_audit_chain (singleton, sequence, head_hash) VALUES (1, 0, zeroblob(32));
CREATE TABLE credbound_login_throttles (user_id TEXT PRIMARY KEY REFERENCES credbound_users(id), failed_attempts INTEGER NOT NULL, locked_until DATETIME, updated_at DATETIME NOT NULL);
CREATE TABLE credbound_password_resets (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), user_id TEXT NOT NULL REFERENCES credbound_users(id), digest BLOB NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME);
CREATE INDEX credbound_password_resets_user_idx ON credbound_password_resets(user_id);
CREATE TABLE credbound_email_authentications (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), user_id TEXT NOT NULL REFERENCES credbound_users(id), email_id TEXT NOT NULL REFERENCES credbound_user_emails(id), digest BLOB NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME);
CREATE INDEX credbound_email_authentications_user_idx ON credbound_email_authentications(user_id);

CREATE TABLE credbound_workspace_invitations (id TEXT PRIMARY KEY CHECK (length(id) = 36 AND id = lower(id) AND substr(id, 15, 1) = '7' AND substr(id, 20, 1) GLOB '[89ab]' AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'), workspace_id TEXT NOT NULL REFERENCES credbound_workspaces(id), email TEXT NOT NULL, role TEXT NOT NULL, invited_by TEXT NOT NULL REFERENCES credbound_users(id), digest BLOB NOT NULL, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, accepted_at DATETIME, accepted_user_id TEXT, revoked_at DATETIME);
CREATE UNIQUE INDEX credbound_workspace_invitations_pending_idx ON credbound_workspace_invitations(workspace_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX credbound_workspace_invitations_page_idx ON credbound_workspace_invitations(workspace_id, created_at DESC, id DESC);
-- Anonymization scrubs a user's accepted invitations; partial because only
-- accepted rows carry the column.
CREATE INDEX credbound_workspace_invitations_accepted_user_idx ON credbound_workspace_invitations(accepted_user_id) WHERE accepted_user_id IS NOT NULL;

-- +goose Down
DROP TABLE credbound_workspace_invitations;
ALTER TABLE credbound_workspaces DROP COLUMN require_mfa;
DROP TABLE credbound_email_authentications;
DROP TABLE credbound_password_resets;
DROP TABLE credbound_login_throttles;
DROP TABLE credbound_audit_chain;
DROP INDEX credbound_audit_events_sequence_idx;
ALTER TABLE credbound_audit_events DROP COLUMN hash;
ALTER TABLE credbound_audit_events DROP COLUMN previous_hash;
ALTER TABLE credbound_audit_events DROP COLUMN sequence;
ALTER TABLE credbound_audit_events DROP COLUMN user_agent;
ALTER TABLE credbound_audit_events DROP COLUMN ip_address;
