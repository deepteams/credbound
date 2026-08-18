package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/sqlite"
)

// CreateSCIMConfiguration stores a workspace's SCIM configuration together
// with its first bearer credential.
func (s *Store) CreateSCIMConfiguration(ctx context.Context, configuration credbound.SCIMConfiguration, credential credbound.SCIMCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := insertSCIMConfiguration(ctx, q, configuration); err != nil {
			return err
		}
		return insertSCIMCredential(ctx, q, credential)
	})
}

// SCIMConfiguration returns the configuration with the given ID.
func (s *Store) SCIMConfiguration(ctx context.Context, id string) (credbound.SCIMConfiguration, error) {
	row, err := s.queries.GetSCIMConfiguration(ctx, id)
	if err != nil {
		return credbound.SCIMConfiguration{}, mapError(err)
	}
	return scimConfigurationFromRow(row)
}

// UpdateSCIMConfiguration persists the configuration's settings and applies
// the recomputed memberships in the same commit.
func (s *Store) UpdateSCIMConfiguration(ctx context.Context, configuration credbound.SCIMConfiguration, memberships []credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		mappings, err := json.Marshal(configuration.GroupRoleMappings)
		if err != nil {
			return err
		}
		count, err := q.UpdateSCIMConfiguration(ctx, db.UpdateSCIMConfigurationParams{
			ID: configuration.ID, DefaultRole: string(configuration.DefaultRole), TrustDirectoryEmails: sqlBool(configuration.TrustDirectoryEmails),
			GroupRoleMappingsJson: string(mappings), UpdatedAt: configuration.UpdatedAt, WorkspaceID: configuration.WorkspaceID,
		})
		if err := affected(count, err); err != nil {
			return err
		}
		for _, membership := range memberships {
			if err := upsertMembership(ctx, q, membership); err != nil {
				return err
			}
		}
		return nil
	})
}

// SCIMConfigurationByCredentialPrefix resolves the configuration and
// credential addressed by a bearer token's lookup prefix.
func (s *Store) SCIMConfigurationByCredentialPrefix(ctx context.Context, prefix string) (credbound.SCIMConfiguration, credbound.SCIMCredential, error) {
	row, err := s.queries.GetSCIMConfigurationByCredentialPrefix(ctx, prefix)
	if err != nil {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, mapError(err)
	}
	configuration, err := scimConfigurationFromCredentialRow(row)
	if err != nil {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, err
	}
	credential := credbound.SCIMCredential{
		ID: row.CredentialID, ConfigurationID: row.ConfigurationID, Prefix: row.Prefix, Digest: row.Digest,
		CreatedAt: row.CredentialCreatedAt, ExpiresAt: timePointer(row.ExpiresAt), LastUsedAt: timePointer(row.LastUsedAt), RevokedAt: timePointer(row.RevokedAt),
	}
	return configuration, credential, nil
}

// SaveSCIMCredential stores an additional bearer credential for a
// configuration.
func (s *Store) SaveSCIMCredential(ctx context.Context, credential credbound.SCIMCredential, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error { return insertSCIMCredential(ctx, q, credential) })
}

// RevokeSCIMCredential marks the configuration's credential revoked.
func (s *Store) RevokeSCIMCredential(ctx context.Context, configurationID, id string, revokedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.RevokeSCIMCredential(ctx, db.RevokeSCIMCredentialParams{
			ConfigurationID: configurationID, ID: id, RevokedAt: nullableTime(&revokedAt),
		})
		return affected(count, err)
	})
}

// TouchSCIMCredential records a successful use of the credential.
func (s *Store) TouchSCIMCredential(ctx context.Context, id string, usedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchSCIMCredential(ctx, db.TouchSCIMCredentialParams{ID: id, LastUsedAt: nullableTime(&usedAt)})
		return affected(count, err)
	})
}

// DisableSCIMConfiguration marks the configuration disabled so its
// credentials stop authenticating.
func (s *Store) DisableSCIMConfiguration(ctx context.Context, id string, disabledAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DisableSCIMConfiguration(ctx, db.DisableSCIMConfigurationParams{ID: id, UpdatedAt: disabledAt})
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.RevokeSCIMCredentials(ctx, db.RevokeSCIMCredentialsParams{ConfigurationID: id, RevokedAt: nullableTime(&disabledAt)}))
	})
}

// CreateSCIMUser atomically creates the Credbound user, email and membership
// for a directory user and links them to the SCIM record.
func (s *Store) CreateSCIMUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, membership credbound.Membership, link credbound.SCIMUser, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := insertUser(ctx, q, user); err != nil {
			return err
		}
		if err := insertEmail(ctx, q, email, credbound.EmailVerificationCredential{}); err != nil {
			return err
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		return insertSCIMUser(ctx, q, link)
	})
}

// AdoptSCIMUser links a directory user to an existing Credbound account,
// installing the membership in the same commit.
func (s *Store) AdoptSCIMUser(ctx context.Context, membership credbound.Membership, link credbound.SCIMUser, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		return insertSCIMUser(ctx, q, link)
	})
}

// SCIMUser returns the configuration's SCIM user with the given ID.
func (s *Store) SCIMUser(ctx context.Context, configurationID, id string) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUser(ctx, db.GetSCIMUserParams{ConfigurationID: configurationID, ID: id})
	if err != nil {
		return credbound.SCIMUser{}, mapError(err)
	}
	return scimUserFromRow(row)
}

// SCIMUserByExternalID resolves the configuration's SCIM user by its
// directory external ID.
func (s *Store) SCIMUserByExternalID(ctx context.Context, configurationID, externalID string) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUserByExternalID(ctx, db.GetSCIMUserByExternalIDParams{ConfigurationID: configurationID, ExternalID: nullableString(externalID)})
	if err != nil {
		return credbound.SCIMUser{}, mapError(err)
	}
	return scimUserFromRow(row)
}

// SCIMUserByUserName resolves the configuration's SCIM user by normalized
// userName.
func (s *Store) SCIMUserByUserName(ctx context.Context, configurationID, userName string) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUserByUserName(ctx, db.GetSCIMUserByUserNameParams{ConfigurationID: configurationID, NormalizedUserName: strings.ToLower(strings.TrimSpace(userName))})
	if err != nil {
		return credbound.SCIMUser{}, mapError(err)
	}
	return scimUserFromRow(row)
}

// UpdateSCIMUser persists the directory record and membership change,
// optionally revoking the user's workspace PATs on deactivation.
func (s *Store) UpdateSCIMUser(ctx context.Context, link credbound.SCIMUser, membership credbound.Membership, revokeWorkspacePATs bool, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		emails, profile, err := encodeSCIMUserJSON(link)
		if err != nil {
			return err
		}
		count, err := q.UpdateSCIMUser(ctx, db.UpdateSCIMUserParams{
			ConfigurationID: link.ConfigurationID, ID: link.ID, ExternalID: nullableString(link.ExternalID),
			NormalizedUserName: link.UserName, DisplayName: link.DisplayName, EmailsJson: string(emails), ProfileJson: string(profile), Active: sqlBool(link.Active),
			UpdatedAt: link.UpdatedAt, DeprovisionedAt: nullableTime(link.DeprovisionedAt),
		})
		if err := affected(count, err); err != nil {
			return err
		}
		if err := upsertMembership(ctx, q, membership); err != nil {
			return err
		}
		if revokeWorkspacePATs {
			return mapError(q.RevokeWorkspacePATs(ctx, db.RevokeWorkspacePATsParams{
				UserID: link.UserID, WorkspaceID: nullableString(membership.WorkspaceID), RevokedAt: nullableTime(&link.UpdatedAt),
			}))
		}
		return nil
	})
}

// SCIMUsers streams the configuration's users matching the filter, newest
// first, as one cursor page.
func (s *Store) SCIMUsers(ctx context.Context, configurationID string, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMUser], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMUser], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		query, args, err := sqliteSCIMUserListQuery(configurationID, filter, cursor, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, query, args...)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.SCIMUser
		count := 0
		for rows.Next() {
			value, err := scanSCIMUser(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.SCIMUser](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.SCIMUser](credbound.PageEnd{}), nil)
	}
}

// UpsertSCIMGroup inserts or replaces a directory group and applies the
// recomputed memberships in the same commit.
func (s *Store) UpsertSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		members, err := json.Marshal(group.MemberIDs)
		if err != nil {
			return err
		}
		if err := q.UpsertSCIMGroup(ctx, db.UpsertSCIMGroupParams{
			ID: group.ID, ConfigurationID: group.ConfigurationID, ExternalID: nullableString(group.ExternalID), DisplayName: group.DisplayName,
			MemberIdsJson: string(members), CreatedAt: group.CreatedAt, UpdatedAt: group.UpdatedAt, DeletedAt: nullableTime(group.DeletedAt),
		}); err != nil {
			return mapError(err)
		}
		for _, membership := range memberships {
			if err := upsertMembership(ctx, q, membership); err != nil {
				return err
			}
		}
		return nil
	})
}

// SCIMGroup returns the configuration's group with the given ID.
func (s *Store) SCIMGroup(ctx context.Context, configurationID, id string) (credbound.SCIMGroup, error) {
	row, err := s.queries.GetSCIMGroup(ctx, db.GetSCIMGroupParams{ConfigurationID: configurationID, ID: id})
	if err != nil {
		return credbound.SCIMGroup{}, mapError(err)
	}
	return scimGroupFromRow(row)
}

// SCIMGroupByExternalID resolves the configuration's group by its directory
// external ID.
func (s *Store) SCIMGroupByExternalID(ctx context.Context, configurationID, externalID string) (credbound.SCIMGroup, error) {
	row, err := s.queries.GetSCIMGroupByExternalID(ctx, db.GetSCIMGroupByExternalIDParams{ConfigurationID: configurationID, ExternalID: nullableString(externalID)})
	if err != nil {
		return credbound.SCIMGroup{}, mapError(err)
	}
	return scimGroupFromRow(row)
}

// DeleteSCIMGroup soft-deletes the group and applies the recomputed
// memberships in the same commit.
func (s *Store) DeleteSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DeleteSCIMGroup(ctx, db.DeleteSCIMGroupParams{
			ConfigurationID: group.ConfigurationID, ID: group.ID, DeletedAt: nullableTime(group.DeletedAt), UpdatedAt: group.UpdatedAt,
		})
		if err := affected(count, err); err != nil {
			return err
		}
		for _, membership := range memberships {
			if err := upsertMembership(ctx, q, membership); err != nil {
				return err
			}
		}
		return nil
	})
}

// SCIMGroups streams the configuration's groups matching the filter, newest
// first, as one cursor page.
func (s *Store) SCIMGroups(ctx context.Context, configurationID string, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMGroup], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMGroup], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		query, args, err := sqliteSCIMGroupListQuery(configurationID, filter, cursor, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		rows, err := s.db.QueryContext(streamCtx, query, args...)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, mapError(err))
			return
		}
		defer rows.Close()
		var last credbound.SCIMGroup
		count := 0
		for rows.Next() {
			value, err := scanSCIMGroup(rows)
			if err != nil {
				yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
				return
			}
			if count == page.Limit {
				yield(credbound.EndEvent[credbound.SCIMGroup](credbound.PageEnd{HasMore: true, NextCursor: encodeCursor(last.CreatedAt, last.ID)}), nil)
				return
			}
			last, count = value, count+1
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		yield(credbound.EndEvent[credbound.SCIMGroup](credbound.PageEnd{}), nil)
	}
}

func insertSCIMConfiguration(ctx context.Context, q *db.Queries, value credbound.SCIMConfiguration) error {
	mappings, err := json.Marshal(value.GroupRoleMappings)
	if err != nil {
		return err
	}
	return mapError(q.InsertSCIMConfiguration(ctx, db.InsertSCIMConfigurationParams{
		ID: value.ID, WorkspaceID: value.WorkspaceID, Enabled: sqlBool(value.Enabled), DefaultRole: string(value.DefaultRole),
		TrustDirectoryEmails: sqlBool(value.TrustDirectoryEmails), GroupRoleMappingsJson: string(mappings), CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}))
}

func insertSCIMCredential(ctx context.Context, q *db.Queries, value credbound.SCIMCredential) error {
	return mapError(q.InsertSCIMCredential(ctx, db.InsertSCIMCredentialParams{
		ID: value.ID, ConfigurationID: value.ConfigurationID, Prefix: value.Prefix, Digest: value.Digest, CreatedAt: value.CreatedAt,
		ExpiresAt: nullableTime(value.ExpiresAt), LastUsedAt: nullableTime(value.LastUsedAt), RevokedAt: nullableTime(value.RevokedAt),
	}))
}

func insertSCIMUser(ctx context.Context, q *db.Queries, value credbound.SCIMUser) error {
	emails, profile, err := encodeSCIMUserJSON(value)
	if err != nil {
		return err
	}
	return mapError(q.InsertSCIMUser(ctx, db.InsertSCIMUserParams{
		ID: value.ID, ConfigurationID: value.ConfigurationID, UserID: value.UserID, ExternalID: nullableString(value.ExternalID),
		NormalizedUserName: value.UserName, DisplayName: value.DisplayName, EmailsJson: string(emails), ProfileJson: string(profile), Active: sqlBool(value.Active),
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, DeprovisionedAt: nullableTime(value.DeprovisionedAt),
	}))
}

func scimConfigurationFromRow(row db.CredboundScimConfiguration) (credbound.SCIMConfiguration, error) {
	return decodeSCIMConfiguration(row.ID, row.WorkspaceID, row.Enabled == 1, row.DefaultRole, row.TrustDirectoryEmails == 1, []byte(row.GroupRoleMappingsJson), row.CreatedAt, row.UpdatedAt)
}

func scimConfigurationFromCredentialRow(row db.GetSCIMConfigurationByCredentialPrefixRow) (credbound.SCIMConfiguration, error) {
	return decodeSCIMConfiguration(row.ID, row.WorkspaceID, row.Enabled == 1, row.DefaultRole, row.TrustDirectoryEmails == 1, []byte(row.GroupRoleMappingsJson), row.CreatedAt, row.UpdatedAt)
}

func decodeSCIMConfiguration(id, workspaceID string, enabled bool, defaultRole string, trust bool, mappingsJSON []byte, createdAt, updatedAt time.Time) (credbound.SCIMConfiguration, error) {
	var mappings []credbound.SCIMGroupRoleMapping
	if err := json.Unmarshal(mappingsJSON, &mappings); err != nil {
		return credbound.SCIMConfiguration{}, err
	}
	return credbound.SCIMConfiguration{
		ID: id, WorkspaceID: workspaceID, Enabled: enabled, DefaultRole: credbound.Role(defaultRole), TrustDirectoryEmails: trust,
		GroupRoleMappings: mappings, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

func scimUserFromRow(row db.CredboundScimUser) (credbound.SCIMUser, error) {
	return decodeSCIMUser(row.ID, row.ConfigurationID, row.UserID, row.ExternalID.String, row.NormalizedUserName, row.DisplayName, []byte(row.EmailsJson), []byte(row.ProfileJson), row.Active == 1, row.CreatedAt, row.UpdatedAt, row.DeprovisionedAt)
}

type scimUserProfile struct {
	Schemas    []string                   `json:"schemas,omitempty"`
	Attributes map[string]json.RawMessage `json:"attributes,omitempty"`
}

func encodeSCIMUserJSON(value credbound.SCIMUser) ([]byte, []byte, error) {
	emails, err := json.Marshal(value.Emails)
	if err != nil {
		return nil, nil, err
	}
	profile, err := json.Marshal(scimUserProfile{Schemas: value.Schemas, Attributes: value.Attributes})
	return emails, profile, err
}

func decodeSCIMUser(id, configurationID, userID, externalID, userName, displayName string, emailsJSON, profileJSON []byte, active bool, createdAt, updatedAt time.Time, deprovisioned sql.NullTime) (credbound.SCIMUser, error) {
	var emails []credbound.SCIMEmail
	if err := json.Unmarshal(emailsJSON, &emails); err != nil {
		return credbound.SCIMUser{}, err
	}
	var profile scimUserProfile
	if err := json.Unmarshal(profileJSON, &profile); err != nil {
		return credbound.SCIMUser{}, err
	}
	return credbound.SCIMUser{
		ID: id, ConfigurationID: configurationID, UserID: userID, ExternalID: externalID, UserName: userName, DisplayName: displayName,
		Schemas: profile.Schemas, Emails: emails, Attributes: profile.Attributes, Active: active, CreatedAt: createdAt, UpdatedAt: updatedAt, DeprovisionedAt: timePointer(deprovisioned),
	}, nil
}

func scimGroupFromRow(row db.CredboundScimGroup) (credbound.SCIMGroup, error) {
	return decodeSCIMGroup(row.ID, row.ConfigurationID, row.ExternalID.String, row.DisplayName, []byte(row.MemberIdsJson), row.CreatedAt, row.UpdatedAt, row.DeletedAt)
}

func decodeSCIMGroup(id, configurationID, externalID, displayName string, membersJSON []byte, createdAt, updatedAt time.Time, deleted sql.NullTime) (credbound.SCIMGroup, error) {
	var members []string
	if err := json.Unmarshal(membersJSON, &members); err != nil {
		return credbound.SCIMGroup{}, err
	}
	return credbound.SCIMGroup{
		ID: id, ConfigurationID: configurationID, ExternalID: externalID, DisplayName: displayName, MemberIDs: members,
		CreatedAt: createdAt, UpdatedAt: updatedAt, DeletedAt: timePointer(deleted),
	}, nil
}

func scanSCIMUser(row scanner) (credbound.SCIMUser, error) {
	var id, configurationID, userID, userName, displayName, emails, profile string
	var external sql.NullString
	var active int64
	var createdAt, updatedAt time.Time
	var deprovisioned sql.NullTime
	if err := row.Scan(&id, &configurationID, &userID, &external, &userName, &displayName, &emails, &profile, &active, &createdAt, &updatedAt, &deprovisioned); err != nil {
		return credbound.SCIMUser{}, err
	}
	return decodeSCIMUser(id, configurationID, userID, external.String, userName, displayName, []byte(emails), []byte(profile), active == 1, createdAt, updatedAt, deprovisioned)
}

func scanSCIMGroup(row scanner) (credbound.SCIMGroup, error) {
	var id, configurationID, displayName, members string
	var external sql.NullString
	var createdAt, updatedAt time.Time
	var deleted sql.NullTime
	if err := row.Scan(&id, &configurationID, &external, &displayName, &members, &createdAt, &updatedAt, &deleted); err != nil {
		return credbound.SCIMGroup{}, err
	}
	return decodeSCIMGroup(id, configurationID, external.String, displayName, []byte(members), createdAt, updatedAt, deleted)
}

func sqliteSCIMUserListQuery(configurationID string, filter credbound.SCIMFilter, cursor cursor, limit int) (string, []any, error) {
	query := `SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound_scim_users WHERE configuration_id = ? AND deprovisioned_at IS NULL`
	args := []any{configurationID}
	switch filter.Attribute {
	case "":
	case "id":
		query, args = query+` AND id = ?`, append(args, filter.Value)
	case "externalId":
		query, args = query+` AND external_id = ?`, append(args, filter.Value)
	case "userName":
		query, args = query+` AND normalized_user_name = ?`, append(args, strings.ToLower(strings.TrimSpace(filter.Value)))
	case "emails.value":
		query, args = query+` AND EXISTS (SELECT 1 FROM json_each(emails_json) e WHERE json_extract(e.value, '$.value') = ?)`, append(args, strings.ToLower(strings.TrimSpace(filter.Value)))
	case "active":
		value := int64(0)
		if strings.EqualFold(filter.Value, "true") {
			value = 1
		} else if !strings.EqualFold(filter.Value, "false") {
			return "", nil, fmt.Errorf("%w: invalid active filter", credbound.ErrInvalidInput)
		}
		query, args = query+` AND active = ?`, append(args, value)
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM user filter", credbound.ErrInvalidInput)
	}
	query += ` AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, cursor.ID, cursor.Time, cursor.Time, cursor.ID, limit)
	return query, args, nil
}

func sqliteSCIMGroupListQuery(configurationID string, filter credbound.SCIMFilter, cursor cursor, limit int) (string, []any, error) {
	query := `SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound_scim_groups WHERE configuration_id = ? AND deleted_at IS NULL`
	args := []any{configurationID}
	switch filter.Attribute {
	case "":
	case "id":
		query, args = query+` AND id = ?`, append(args, filter.Value)
	case "externalId":
		query, args = query+` AND external_id = ?`, append(args, filter.Value)
	case "displayName":
		query, args = query+` AND display_name = ?`, append(args, filter.Value)
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM group filter", credbound.ErrInvalidInput)
	}
	query += ` AND (? = '' OR created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, cursor.ID, cursor.Time, cursor.Time, cursor.ID, limit)
	return query, args, nil
}

func sqlBool(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

// SCIMConfigurations streams the workspace's provisioning domains, oldest
// first.
func (s *Store) SCIMConfigurations(ctx context.Context, workspaceID string) iter.Seq2[credbound.SCIMConfiguration, error] {
	return func(yield func(credbound.SCIMConfiguration, error) bool) {
		rows, err := s.queries.ListSCIMConfigurationsByWorkspace(ctx, workspaceID)
		if err != nil {
			yield(credbound.SCIMConfiguration{}, mapError(err))
			return
		}
		for _, row := range rows {
			value, err := scimConfigurationFromRow(row)
			if err != nil {
				yield(credbound.SCIMConfiguration{}, err)
				return
			}
			if !yield(value, nil) {
				return
			}
		}
	}
}

// SCIMCredentials streams the configuration's bearer credentials, oldest
// first, with digests omitted.
func (s *Store) SCIMCredentials(ctx context.Context, configurationID string) iter.Seq2[credbound.SCIMCredential, error] {
	return func(yield func(credbound.SCIMCredential, error) bool) {
		rows, err := s.queries.ListSCIMCredentials(ctx, configurationID)
		if err != nil {
			yield(credbound.SCIMCredential{}, mapError(err))
			return
		}
		for _, row := range rows {
			value := credbound.SCIMCredential{
				ID: row.ID, ConfigurationID: row.ConfigurationID, Prefix: row.Prefix,
				CreatedAt: row.CreatedAt, ExpiresAt: timePointer(row.ExpiresAt), LastUsedAt: timePointer(row.LastUsedAt), RevokedAt: timePointer(row.RevokedAt),
			}
			if !yield(value, nil) {
				return
			}
		}
	}
}

// SCIMUsersByUser streams every tenant-scoped SCIM profile linked to the
// user across configurations, oldest first, for the PrivacyStore capability.
func (s *Store) SCIMUsersByUser(ctx context.Context, userID string) iter.Seq2[credbound.SCIMUser, error] {
	return func(yield func(credbound.SCIMUser, error) bool) {
		rows, err := s.queries.ListSCIMUsersForUser(ctx, userID)
		if err != nil {
			yield(credbound.SCIMUser{}, mapError(err))
			return
		}
		for _, row := range rows {
			value, err := scimUserFromRow(row)
			if err != nil {
				yield(credbound.SCIMUser{}, err)
				return
			}
			if !yield(value, nil) {
				return
			}
		}
	}
}

var _ credbound.SCIMStore = (*Store)(nil)
var _ credbound.PrivacyStore = (*Store)(nil)
