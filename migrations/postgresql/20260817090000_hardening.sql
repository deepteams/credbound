-- +goose Up
ALTER TABLE credbound.workspaces ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;
ALTER TABLE credbound.audit_events ADD COLUMN ip_address text NOT NULL DEFAULT '';
ALTER TABLE credbound.audit_events ADD COLUMN user_agent text NOT NULL DEFAULT '';
ALTER TABLE credbound.audit_events ADD COLUMN sequence bigint;
ALTER TABLE credbound.audit_events ADD COLUMN previous_hash bytea;
ALTER TABLE credbound.audit_events ADD COLUMN hash bytea;
CREATE UNIQUE INDEX audit_events_sequence_idx ON credbound.audit_events(sequence) WHERE sequence IS NOT NULL;
CREATE TABLE credbound.audit_chain (singleton integer PRIMARY KEY CHECK (singleton = 1), sequence bigint NOT NULL, head_hash bytea NOT NULL);
INSERT INTO credbound.audit_chain (singleton, sequence, head_hash) VALUES (1, 0, decode(repeat('00', 32), 'hex'));
CREATE TABLE credbound.login_throttles (user_id uuid PRIMARY KEY REFERENCES credbound.users(id), failed_attempts bigint NOT NULL, locked_until timestamptz, updated_at timestamptz NOT NULL);
CREATE TABLE credbound.password_resets (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), user_id uuid NOT NULL REFERENCES credbound.users(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE INDEX password_resets_user_idx ON credbound.password_resets(user_id);
CREATE TABLE credbound.email_authentications (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), user_id uuid NOT NULL REFERENCES credbound.users(id), email_id uuid NOT NULL REFERENCES credbound.user_emails(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
CREATE INDEX email_authentications_user_idx ON credbound.email_authentications(user_id);

CREATE TABLE credbound.workspace_invitations (id uuid PRIMARY KEY CHECK (substring(id::text from 15 for 1) = '7' AND substring(id::text from 20 for 1) IN ('8', '9', 'a', 'b')), workspace_id uuid NOT NULL REFERENCES credbound.workspaces(id), email text NOT NULL, role text NOT NULL, invited_by uuid NOT NULL REFERENCES credbound.users(id), digest bytea NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, accepted_at timestamptz, accepted_user_id uuid, revoked_at timestamptz);
CREATE UNIQUE INDEX workspace_invitations_pending_idx ON credbound.workspace_invitations(workspace_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX workspace_invitations_page_idx ON credbound.workspace_invitations(workspace_id, created_at DESC, id DESC);
-- Anonymization scrubs a user's accepted invitations; partial because only
-- accepted rows carry the column.
CREATE INDEX workspace_invitations_accepted_user_idx ON credbound.workspace_invitations(accepted_user_id) WHERE accepted_user_id IS NOT NULL;

-- +goose Down
DROP TABLE credbound.workspace_invitations;
ALTER TABLE credbound.workspaces DROP COLUMN require_mfa;
DROP TABLE credbound.email_authentications;
DROP TABLE credbound.password_resets;
DROP TABLE credbound.login_throttles;
DROP TABLE credbound.audit_chain;
DROP INDEX credbound.audit_events_sequence_idx;
ALTER TABLE credbound.audit_events DROP COLUMN hash;
ALTER TABLE credbound.audit_events DROP COLUMN previous_hash;
ALTER TABLE credbound.audit_events DROP COLUMN sequence;
ALTER TABLE credbound.audit_events DROP COLUMN user_agent;
ALTER TABLE credbound.audit_events DROP COLUMN ip_address;
