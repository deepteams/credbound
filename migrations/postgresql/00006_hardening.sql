-- +goose Up
ALTER TABLE credbound_workspaces ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;
ALTER TABLE credbound_audit_events ADD COLUMN ip_address text NOT NULL DEFAULT '';
ALTER TABLE credbound_audit_events ADD COLUMN user_agent text NOT NULL DEFAULT '';
ALTER TABLE credbound_audit_events ADD COLUMN sequence bigint;
ALTER TABLE credbound_audit_events ADD COLUMN previous_hash bytea;
ALTER TABLE credbound_audit_events ADD COLUMN hash bytea;
CREATE UNIQUE INDEX credbound_audit_events_sequence_idx ON credbound_audit_events(sequence) WHERE sequence IS NOT NULL;
CREATE TABLE credbound_audit_chain (singleton integer PRIMARY KEY CHECK (singleton = 1), sequence bigint NOT NULL, head_hash bytea NOT NULL);
INSERT INTO credbound_audit_chain (singleton, sequence, head_hash) VALUES (1, 0, decode(repeat('00', 32), 'hex'));
CREATE TABLE credbound_login_throttles (user_id uuid PRIMARY KEY REFERENCES credbound_users(id), failed_attempts bigint NOT NULL, locked_until timestamptz, updated_at timestamptz NOT NULL);
CREATE TABLE credbound_password_resets (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), user_id uuid NOT NULL REFERENCES credbound_users(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE INDEX credbound_password_resets_user_idx ON credbound_password_resets(user_id);
CREATE TABLE credbound_email_authentications (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), user_id uuid NOT NULL REFERENCES credbound_users(id), email_id uuid NOT NULL REFERENCES credbound_user_emails(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE INDEX credbound_email_authentications_user_idx ON credbound_email_authentications(user_id);

CREATE TABLE credbound_workspace_invitations (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), workspace_id uuid NOT NULL REFERENCES credbound_workspaces(id), email text NOT NULL, role text NOT NULL, invited_by uuid NOT NULL REFERENCES credbound_users(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, accepted_at timestamptz, accepted_user_id uuid, revoked_at timestamptz);
CREATE UNIQUE INDEX credbound_workspace_invitations_pending_idx ON credbound_workspace_invitations(workspace_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX credbound_workspace_invitations_page_idx ON credbound_workspace_invitations(workspace_id, created_at DESC, id DESC);

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
