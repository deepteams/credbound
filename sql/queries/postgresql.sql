-- name: ClaimBootstrap :exec
INSERT INTO credbound.instance (singleton, initialized_at) VALUES (true, $1);

-- name: InsertUser :exec
INSERT INTO credbound.users (id, display_name, disabled, last_seen_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetUserByEmail :one
SELECT u.id, primary_email.address AS email, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound.users u
JOIN credbound.user_emails login_email ON login_email.user_id = u.id
JOIN credbound.user_emails primary_email ON primary_email.user_id = u.id AND primary_email.is_primary
WHERE login_email.address = $1 AND login_email.verified_at IS NOT NULL;

-- name: GetUserByID :one
SELECT u.id, primary_email.address AS email, u.display_name, u.disabled, u.last_seen_at, u.created_at, u.updated_at
FROM credbound.users u
JOIN credbound.user_emails primary_email ON primary_email.user_id = u.id AND primary_email.is_primary
WHERE u.id = $1;

-- name: SetUserDisabled :execrows
UPDATE credbound.users SET disabled = $2, updated_at = $3 WHERE id = $1;

-- name: UpdateUser :execrows
UPDATE credbound.users SET display_name = $2, updated_at = $3 WHERE id = $1;

-- name: ScrubUserProfile :execrows
UPDATE credbound.users SET display_name = '', disabled = true, updated_at = $2 WHERE id = $1;

-- name: ScrubUserEmails :exec
UPDATE credbound.user_emails SET address = 'anonymized-' || id::text || '@invalid', updated_at = $2 WHERE user_id = $1;

-- name: ScrubUserSSOEmails :exec
UPDATE credbound.sso_identities SET email = '' WHERE user_id = $1;

-- name: ScrubUserPATNames :exec
UPDATE credbound.personal_access_tokens SET name = '' WHERE user_id = $1;

-- name: ScrubUserSessions :exec
UPDATE credbound.sessions SET user_agent = '', ip_address = '' WHERE user_id = $1;

-- name: CountEnabledRootAdministrators :one
SELECT count(*) FROM credbound.instance_administrators a
JOIN credbound.users u ON u.id = a.user_id
WHERE a.role = 'root' AND NOT u.disabled;

-- name: LockRootAdministrators :many
SELECT user_id FROM credbound.instance_administrators
WHERE role = 'root'
ORDER BY user_id
FOR UPDATE;

-- name: LockUserAdminWorkspaces :many
SELECT w.id
FROM credbound.workspaces w
JOIN credbound.memberships m ON m.workspace_id = w.id
WHERE m.user_id = $1 AND m.role = 'admin' AND m.status = 'active'
ORDER BY w.id
FOR UPDATE OF w;

-- name: CountWorkspacesOrphanedByUserDisable :one
SELECT count(*)
FROM credbound.memberships target
WHERE target.user_id = $1 AND target.role = 'admin' AND target.status = 'active'
  AND NOT EXISTS (
    SELECT 1
    FROM credbound.memberships other
    JOIN credbound.users other_user ON other_user.id = other.user_id
    WHERE other.workspace_id = target.workspace_id
      AND other.user_id <> target.user_id
      AND other.role = 'admin'
      AND other.status = 'active'
      AND NOT other_user.disabled
  );

-- name: RevokeUserPATs :exec
UPDATE credbound.personal_access_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: TouchUserLastSeen :execrows
UPDATE credbound.users SET last_seen_at = $2 WHERE id = $1;

-- name: GetLoginThrottle :one
SELECT user_id, failed_attempts, locked_until, updated_at FROM credbound.login_throttles WHERE user_id = $1;

-- name: UpsertLoginFailure :one
INSERT INTO credbound.login_throttles (user_id, failed_attempts, locked_until, updated_at) VALUES ($1, 1, NULL, $2)
ON CONFLICT (user_id) DO UPDATE SET failed_attempts = credbound.login_throttles.failed_attempts + 1, updated_at = excluded.updated_at
RETURNING failed_attempts;

-- name: LockLoginThrottle :execrows
UPDATE credbound.login_throttles SET locked_until = $2 WHERE user_id = $1;

-- name: ClearLoginThrottle :exec
DELETE FROM credbound.login_throttles WHERE user_id = $1;

-- name: InsertPasswordReset :exec
INSERT INTO credbound.password_resets (id, user_id, digest, created_at, expires_at, used_at) VALUES ($1, $2, $3, $4, $5, NULL);

-- name: GetPasswordReset :one
SELECT id, user_id, digest, created_at, expires_at, used_at FROM credbound.password_resets WHERE id = $1;

-- name: ConsumePasswordReset :execrows
UPDATE credbound.password_resets SET used_at = $2 WHERE id = $1 AND used_at IS NULL;

-- name: DeleteOtherPasswordResets :exec
DELETE FROM credbound.password_resets WHERE user_id = $1 AND id != $2;

-- name: InsertEmailAuthentication :exec
INSERT INTO credbound.email_authentications (id, user_id, email_id, digest, created_at, expires_at, used_at) VALUES ($1, $2, $3, $4, $5, $6, NULL);

-- name: GetEmailAuthentication :one
SELECT id, user_id, email_id, digest, created_at, expires_at, used_at FROM credbound.email_authentications WHERE id = $1;

-- name: ConsumeEmailAuthentication :execrows
UPDATE credbound.email_authentications SET used_at = $3 WHERE id = $1 AND user_id = $2 AND used_at IS NULL;

-- name: InsertUserEmail :exec
INSERT INTO credbound.user_emails (id, user_id, address, is_primary, verified_at, verification_digest, verification_expires_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetEmailVerification :one
SELECT id, user_id, address, is_primary, verified_at, verification_digest, verification_expires_at, created_at, updated_at
FROM credbound.user_emails WHERE id = $1;

-- name: VerifyEmail :execrows
UPDATE credbound.user_emails
SET verified_at = $2, verification_digest = NULL, verification_expires_at = NULL, updated_at = $2
WHERE id = $1 AND verified_at IS NULL;

-- name: ClearPrimaryEmails :exec
UPDATE credbound.user_emails SET is_primary = false, updated_at = $2 WHERE user_id = $1 AND is_primary;

-- name: SetPrimaryEmail :execrows
UPDATE credbound.user_emails SET is_primary = true, updated_at = $3
WHERE id = $2 AND user_id = $1 AND verified_at IS NOT NULL;

-- name: DeleteEmail :execrows
DELETE FROM credbound.user_emails WHERE id = $2 AND user_id = $1 AND NOT is_primary;

-- name: CountVerifiedEmails :one
SELECT count(*) FROM credbound.user_emails WHERE user_id = $1 AND verified_at IS NOT NULL;

-- name: InsertPassword :exec
INSERT INTO credbound.password_credentials (user_id, hash, updated_at) VALUES ($1, $2, $3);

-- name: GetPassword :one
SELECT user_id, hash, updated_at FROM credbound.password_credentials WHERE user_id = $1;

-- name: ReplacePassword :execrows
UPDATE credbound.password_credentials SET hash = $2, updated_at = $3 WHERE user_id = $1;

-- name: InsertWorkspace :exec
INSERT INTO credbound.workspaces (id, name, created_at, updated_at, disabled_at, require_mfa) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetWorkspace :one
SELECT id, name, created_at, updated_at, disabled_at, require_mfa FROM credbound.workspaces WHERE id = $1;

-- name: LockWorkspace :one
SELECT id FROM credbound.workspaces WHERE id = $1 FOR UPDATE;

-- name: UpdateWorkspace :execrows
UPDATE credbound.workspaces SET name = $2, updated_at = $3, require_mfa = $4 WHERE id = $1;

-- name: SetWorkspaceDisabled :execrows
UPDATE credbound.workspaces SET disabled_at = $2, updated_at = $3 WHERE id = $1;

-- name: RevokeAllWorkspacePATs :exec
UPDATE credbound.personal_access_tokens SET revoked_at = $2 WHERE workspace_id = $1 AND revoked_at IS NULL;

-- name: InsertWorkspaceInvitation :exec
INSERT INTO credbound.workspace_invitations (id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, NULL, NULL);

-- name: GetWorkspaceInvitation :one
SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound.workspace_invitations WHERE id = $1;

-- name: GetPendingWorkspaceInvitation :one
SELECT id, workspace_id, email, role, invited_by, digest, created_at, expires_at, accepted_at, accepted_user_id, revoked_at
FROM credbound.workspace_invitations WHERE workspace_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: AcceptWorkspaceInvitation :execrows
UPDATE credbound.workspace_invitations SET accepted_at = $2, accepted_user_id = $3 WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: RevokeWorkspaceInvitation :execrows
UPDATE credbound.workspace_invitations SET revoked_at = $3 WHERE id = $2 AND workspace_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: UpsertMembership :exec
INSERT INTO credbound.memberships (workspace_id, user_id, role, status, provisioning_source, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status, provisioning_source = EXCLUDED.provisioning_source, updated_at = EXCLUDED.updated_at;

-- name: GetMembership :one
SELECT workspace_id, user_id, role, status, provisioning_source, created_at, updated_at FROM credbound.memberships WHERE workspace_id = $1 AND user_id = $2;

-- name: CountActiveWorkspaceAdministrators :one
SELECT count(*)
FROM credbound.memberships m
JOIN credbound.users u ON u.id = m.user_id
WHERE m.workspace_id = $1 AND m.role = 'admin' AND m.status = 'active' AND NOT u.disabled;

-- name: DeleteMembership :execrows
DELETE FROM credbound.memberships WHERE workspace_id = $1 AND user_id = $2;

-- name: UpsertInstanceAdministrator :exec
INSERT INTO credbound.instance_administrators (user_id, role, created_at, updated_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = EXCLUDED.updated_at;

-- name: GetInstanceAdministrator :one
SELECT user_id, role, created_at, updated_at FROM credbound.instance_administrators WHERE user_id = $1;

-- name: DeleteInstanceAdministrator :execrows
DELETE FROM credbound.instance_administrators WHERE user_id = $1;

-- name: CountRootAdministrators :one
SELECT count(*) FROM credbound.instance_administrators WHERE role = 'root';

-- name: GetSSOIdentity :one
SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound.sso_identities WHERE provider_configuration_id = $1 AND issuer = $2 AND subject = $3;

-- name: InsertSSOIdentity :exec
INSERT INTO credbound.sso_identities (id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetSSOIdentityByID :one
SELECT id, user_id, provider_configuration_id, provider_kind, issuer, subject, email, created_at, last_used_at
FROM credbound.sso_identities WHERE id = $1;

-- name: TouchSSOIdentity :execrows
UPDATE credbound.sso_identities SET last_used_at = $3 WHERE id = $2 AND user_id = $1;

-- name: DeleteSSOIdentity :execrows
DELETE FROM credbound.sso_identities WHERE id = $2 AND user_id = $1;

-- name: SaveTOTPEnrollment :execrows
INSERT INTO credbound.totp_factors (user_id, encrypted_secret, active, last_used_step, created_at, updated_at)
VALUES ($1, $2, false, 0, $3, $4)
ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret, active = false, last_used_step = 0, updated_at = EXCLUDED.updated_at
WHERE NOT credbound.totp_factors.active;

-- name: GetTOTP :one
SELECT user_id, encrypted_secret, active, last_used_step, created_at, updated_at FROM credbound.totp_factors WHERE user_id = $1;

-- name: ActivateTOTP :execrows
UPDATE credbound.totp_factors SET encrypted_secret = $2, active = true, last_used_step = $3, updated_at = $4 WHERE user_id = $1 AND NOT active;

-- name: UseTOTP :execrows
UPDATE credbound.totp_factors SET last_used_step = $2, updated_at = $3 WHERE user_id = $1 AND active AND last_used_step < $2;

-- name: DeleteTOTP :execrows
DELETE FROM credbound.totp_factors WHERE user_id = $1;

-- name: DeleteRecoveryCodes :exec
DELETE FROM credbound.recovery_codes WHERE user_id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO credbound.recovery_codes (user_id, digest, used_at) VALUES ($1, $2, NULL);

-- name: ConsumeRecoveryCode :execrows
UPDATE credbound.recovery_codes SET used_at = $3 WHERE user_id = $1 AND digest = $2 AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM credbound.recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: InsertPasskey :exec
INSERT INTO credbound.passkeys (id, user_id, name, credential_id, credential_json, created_at, last_used_at) VALUES ($1, $2, $3, $4, $5, $6, NULL);

-- name: TouchPasskey :execrows
UPDATE credbound.passkeys SET credential_json = $3, last_used_at = $4 WHERE user_id = $1 AND credential_id = $2;

-- name: DeletePasskey :execrows
DELETE FROM credbound.passkeys WHERE user_id = $1 AND id = $2;

-- name: DeleteUserPasskeys :exec
DELETE FROM credbound.passkeys WHERE user_id = $1;

-- name: InsertPAT :exec
INSERT INTO credbound.personal_access_tokens (id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL, NULL);

-- name: GetPATByPrefix :one
SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound.personal_access_tokens WHERE prefix = $1;

-- name: GetPATByID :one
SELECT id, user_id, name, prefix, digest, workspace_id, scopes_json, created_at, expires_at, last_used_at, revoked_at
FROM credbound.personal_access_tokens WHERE id = $1;

-- name: TouchPAT :execrows
UPDATE credbound.personal_access_tokens SET last_used_at = $2 WHERE id = $1;

-- name: RevokePAT :execrows
UPDATE credbound.personal_access_tokens SET revoked_at = $3 WHERE user_id = $1 AND id = $2;

-- name: InsertSession :exec
INSERT INTO credbound.sessions (id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, digest, created_at, last_seen_at, expires_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NULL);

-- name: GetSession :one
SELECT id, user_id, method, level, authenticated_at, second_factor_required, user_agent, ip_address, digest, created_at, last_seen_at, expires_at, revoked_at
FROM credbound.sessions WHERE id = $1;

-- name: TouchSession :execrows
UPDATE credbound.sessions SET last_seen_at = $2 WHERE id = $1;

-- name: RevokeSessionByID :execrows
UPDATE credbound.sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL;

-- name: RevokeUserSessions :exec
UPDATE credbound.sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: InsertAudit :exec
INSERT INTO credbound.audit_events (id, occurred_at, actor_kind, actor_id, action, resource_type, resource_id, workspace_id, outcome, reason, ip_address, user_agent, sequence, previous_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: GetAuditChainHead :one
SELECT sequence, head_hash FROM credbound.audit_chain WHERE singleton = 1 FOR UPDATE;

-- name: UpdateAuditChainHead :execrows
UPDATE credbound.audit_chain SET sequence = $1, head_hash = $2 WHERE singleton = 1;

-- name: InsertSCIMConfiguration :exec
INSERT INTO credbound.scim_configurations (id, workspace_id, enabled, default_role, trust_directory_emails, group_role_mappings_json, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetSCIMConfiguration :one
SELECT id, workspace_id, enabled, default_role, trust_directory_emails, group_role_mappings_json, created_at, updated_at
FROM credbound.scim_configurations WHERE id = $1;

-- name: UpdateSCIMConfiguration :execrows
UPDATE credbound.scim_configurations
SET default_role = $2, trust_directory_emails = $3, group_role_mappings_json = $4, updated_at = $5
WHERE id = $1 AND workspace_id = $6;

-- name: GetSCIMConfigurationByCredentialPrefix :one
SELECT c.id, c.workspace_id, c.enabled, c.default_role, c.trust_directory_emails, c.group_role_mappings_json, c.created_at, c.updated_at,
       k.id AS credential_id, k.configuration_id, k.prefix, k.digest, k.created_at AS credential_created_at, k.expires_at, k.last_used_at, k.revoked_at
FROM credbound.scim_credentials k
JOIN credbound.scim_configurations c ON c.id = k.configuration_id
WHERE k.prefix = $1;

-- name: InsertSCIMCredential :exec
INSERT INTO credbound.scim_credentials (id, configuration_id, prefix, digest, created_at, expires_at, last_used_at, revoked_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: TouchSCIMCredential :execrows
UPDATE credbound.scim_credentials SET last_used_at = $2 WHERE id = $1;

-- name: RevokeSCIMCredential :execrows
UPDATE credbound.scim_credentials SET revoked_at = $3 WHERE configuration_id = $1 AND id = $2;

-- name: DisableSCIMConfiguration :execrows
UPDATE credbound.scim_configurations SET enabled = false, updated_at = $2 WHERE id = $1;

-- name: RevokeSCIMCredentials :exec
UPDATE credbound.scim_credentials SET revoked_at = $2 WHERE configuration_id = $1 AND revoked_at IS NULL;

-- name: InsertSCIMUser :exec
INSERT INTO credbound.scim_users (id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: GetSCIMUser :one
SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound.scim_users WHERE configuration_id = $1 AND id = $2;

-- name: GetSCIMUserByExternalID :one
SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound.scim_users WHERE configuration_id = $1 AND external_id = $2;

-- name: GetSCIMUserByUserName :one
SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound.scim_users WHERE configuration_id = $1 AND normalized_user_name = $2;

-- name: UpdateSCIMUser :execrows
UPDATE credbound.scim_users SET external_id = $3, normalized_user_name = $4, display_name = $5, emails_json = $6, profile_json = $7, active = $8, updated_at = $9, deprovisioned_at = $10
WHERE configuration_id = $1 AND id = $2;

-- name: RevokeWorkspacePATs :exec
UPDATE credbound.personal_access_tokens SET revoked_at = $3 WHERE user_id = $1 AND workspace_id = $2 AND revoked_at IS NULL;

-- name: UpsertSCIMGroup :exec
INSERT INTO credbound.scim_groups (id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (id) DO UPDATE SET external_id = EXCLUDED.external_id, display_name = EXCLUDED.display_name, member_ids_json = EXCLUDED.member_ids_json, updated_at = EXCLUDED.updated_at, deleted_at = EXCLUDED.deleted_at;

-- name: GetSCIMGroup :one
SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound.scim_groups WHERE configuration_id = $1 AND id = $2 AND deleted_at IS NULL;

-- name: GetSCIMGroupByExternalID :one
SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound.scim_groups WHERE configuration_id = $1 AND external_id = $2 AND deleted_at IS NULL;

-- name: DeleteSCIMGroup :execrows
UPDATE credbound.scim_groups SET deleted_at = $3, updated_at = $4 WHERE configuration_id = $1 AND id = $2 AND deleted_at IS NULL;

-- OAuth/OIDC writes and point lookups are generated. Only public cursor streams
-- remain hand-written in the store because their row delivery is lazy.

-- name: OAuthInsertIssuer :exec
INSERT INTO credbound.oauth_issuers (id, issuer, created_at, data_json) VALUES ($1, $2, $3, $4);

-- name: OAuthUpdateIssuer :execrows
UPDATE credbound.oauth_issuers SET data_json = $3 WHERE id = $1 AND issuer = $2;

-- name: OAuthUpdateIssuerJSON :execrows
UPDATE credbound.oauth_issuers SET data_json = $2 WHERE id = $1;

-- name: OAuthIssuerJSONByID :one
SELECT data_json FROM credbound.oauth_issuers WHERE id = $1;

-- name: OAuthLockIssuer :one
SELECT id FROM credbound.oauth_issuers WHERE id = $1 FOR UPDATE;

-- name: OAuthIssuerJSONByURL :one
SELECT data_json FROM credbound.oauth_issuers WHERE issuer = $1;

-- name: OAuthInsertResource :exec
INSERT INTO credbound.oauth_resources (id, issuer_id, workspace_id, resource, created_at, data_json) VALUES ($1, $2, $3, $4, $5, $6);

-- name: OAuthUpdateResourceJSON :execrows
UPDATE credbound.oauth_resources SET data_json = $2 WHERE id = $1;

-- name: OAuthResourceJSONByID :one
SELECT data_json FROM credbound.oauth_resources WHERE id = $1;

-- name: OAuthResourceJSONByURI :one
SELECT data_json FROM credbound.oauth_resources WHERE resource = $1;

-- name: OAuthInsertClient :exec
INSERT INTO credbound.oauth_clients (id, issuer_id, client_id, created_at, data_json) VALUES ($1, $2, $3, $4, $5);

-- name: OAuthUpsertCIMDClient :exec
INSERT INTO credbound.oauth_clients (id, issuer_id, client_id, created_at, data_json) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (issuer_id, client_id) DO UPDATE SET data_json = EXCLUDED.data_json;

-- name: OAuthUpdateClientJSON :execrows
UPDATE credbound.oauth_clients SET data_json = $2 WHERE id = $1;

-- name: OAuthClientJSONByID :one
SELECT data_json FROM credbound.oauth_clients WHERE id = $1;

-- name: OAuthClientJSONByClientID :one
SELECT data_json FROM credbound.oauth_clients WHERE issuer_id = $1 AND client_id = $2;

-- name: OAuthClientJSONsByIssuer :many
SELECT data_json FROM credbound.oauth_clients WHERE issuer_id = $1;

-- name: OAuthInsertInitialAccessToken :exec
INSERT INTO credbound.oauth_initial_access_tokens (id, issuer_id, prefix, registration_count, max_registrations, expires_at, revoked_at, data_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: OAuthInitialAccessTokenJSONByPrefix :one
SELECT data_json FROM credbound.oauth_initial_access_tokens WHERE prefix = $1;

-- name: OAuthInitialAccessTokenJSONByID :one
SELECT data_json FROM credbound.oauth_initial_access_tokens WHERE id = $1;

-- name: OAuthInitialAccessTokenJSONByIDAndIssuer :one
SELECT data_json FROM credbound.oauth_initial_access_tokens WHERE id = $1 AND issuer_id = $2;

-- name: OAuthUseInitialAccessToken :execrows
UPDATE credbound.oauth_initial_access_tokens
SET registration_count = $2, data_json = $3
WHERE id = $1 AND registration_count = $4 AND revoked_at IS NULL AND expires_at > $5;

-- name: OAuthRevokeInitialAccessToken :execrows
UPDATE credbound.oauth_initial_access_tokens SET revoked_at = $2, data_json = $3 WHERE id = $1;

-- name: OAuthInsertGrant :exec
INSERT INTO credbound.oauth_grants (id, client_record_id, resource_id, user_id, workspace_id, created_at, data_json)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: OAuthGrantJSONByID :one
SELECT data_json FROM credbound.oauth_grants WHERE id = $1;

-- name: OAuthGrantRecords :many
SELECT id, data_json FROM credbound.oauth_grants;

-- name: OAuthGrantIDsByUser :many
SELECT id FROM credbound.oauth_grants WHERE user_id = $1;

-- name: OAuthGrantIDsByClient :many
SELECT id FROM credbound.oauth_grants WHERE client_record_id = $1;

-- name: OAuthGrantIDsByResource :many
SELECT id FROM credbound.oauth_grants WHERE resource_id = $1;

-- name: OAuthUpdateGrantJSON :execrows
UPDATE credbound.oauth_grants SET data_json = $2 WHERE id = $1;

-- name: OAuthInsertAuthorizationCode :exec
INSERT INTO credbound.oauth_authorization_codes (id, prefix, grant_id, used_at, expires_at, data_json) VALUES ($1, $2, $3, $4, $5, $6);

-- name: OAuthAuthorizationCodeJSONByPrefix :one
SELECT data_json FROM credbound.oauth_authorization_codes WHERE prefix = $1;

-- name: OAuthAuthorizationCodeJSONByID :one
SELECT data_json FROM credbound.oauth_authorization_codes WHERE id = $1;

-- name: OAuthConsumeAuthorizationCode :execrows
UPDATE credbound.oauth_authorization_codes SET used_at = $2, data_json = $3
WHERE id = $1 AND used_at IS NULL AND expires_at > $4;

-- name: OAuthInsertAccessToken :exec
INSERT INTO credbound.oauth_access_tokens (id, prefix, grant_id, data_json) VALUES ($1, $2, $3, $4);

-- name: OAuthAccessTokenJSONByPrefix :one
SELECT data_json FROM credbound.oauth_access_tokens WHERE prefix = $1;

-- name: OAuthAccessTokenJSONByID :one
SELECT data_json FROM credbound.oauth_access_tokens WHERE id = $1;

-- name: OAuthAccessTokenRecordsByGrant :many
SELECT id, data_json FROM credbound.oauth_access_tokens WHERE grant_id = $1;

-- name: OAuthUpdateAccessTokenJSON :execrows
UPDATE credbound.oauth_access_tokens SET data_json = $2 WHERE id = $1;

-- name: OAuthInsertRefreshToken :exec
INSERT INTO credbound.oauth_refresh_tokens (id, family_id, prefix, grant_id, used_at, revoked_at, expires_at, data_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: OAuthRefreshTokenByPrefix :one
SELECT data_json, used_at, revoked_at FROM credbound.oauth_refresh_tokens WHERE prefix = $1;

-- name: OAuthRefreshTokenJSONByID :one
SELECT data_json FROM credbound.oauth_refresh_tokens WHERE id = $1;

-- name: OAuthRefreshTokenRecordsByGrant :many
SELECT id, data_json FROM credbound.oauth_refresh_tokens WHERE grant_id = $1 AND revoked_at IS NULL;

-- name: OAuthConsumeRefreshToken :execrows
UPDATE credbound.oauth_refresh_tokens SET used_at = $2, data_json = $3
WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $4;

-- name: OAuthRevokeRefreshToken :execrows
UPDATE credbound.oauth_refresh_tokens SET revoked_at = $2, data_json = $3 WHERE id = $1;

-- name: OAuthRevokeRefreshFamily :execrows
UPDATE credbound.oauth_refresh_tokens SET revoked_at = $2 WHERE family_id = $1 AND revoked_at IS NULL;

-- name: OAuthRefreshFamilyExists :one
SELECT EXISTS(SELECT 1 FROM credbound.oauth_refresh_tokens WHERE family_id = $1);

-- name: InsertWorkspaceDomain :exec
INSERT INTO credbound.workspace_domains (id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: GetWorkspaceDomain :one
SELECT id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at
FROM credbound.workspace_domains WHERE id = $1;

-- name: GetConfirmedWorkspaceDomainByName :one
SELECT id, workspace_id, domain, challenge, confirmed_at, auto_join, auto_join_role, sso_provider_configuration_id, enforce_sso, created_at, updated_at
FROM credbound.workspace_domains WHERE domain = $1 AND confirmed_at IS NOT NULL;

-- name: ConfirmWorkspaceDomain :execrows
UPDATE credbound.workspace_domains SET confirmed_at = $2, updated_at = $2 WHERE id = $1 AND confirmed_at IS NULL;

-- name: UpdateWorkspaceDomainPolicy :execrows
UPDATE credbound.workspace_domains SET auto_join = $2, auto_join_role = $3, sso_provider_configuration_id = $4, enforce_sso = $5, updated_at = $6
WHERE id = $1 AND confirmed_at IS NOT NULL;

-- name: DeleteWorkspaceDomain :execrows
DELETE FROM credbound.workspace_domains WHERE id = $1;

-- name: InsertConsumedCeremony :exec
INSERT INTO credbound.consumed_ceremonies (id, expires_at) VALUES ($1, $2);

-- name: PruneConsumedCeremonies :exec
DELETE FROM credbound.consumed_ceremonies WHERE expires_at < $1;
