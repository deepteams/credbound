package postgresql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"iter"
	"strings"
	"time"

	"github.com/deepteams/credbound"
	db "github.com/deepteams/credbound/internal/sqlc/postgresql"
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
func (s *Store) SCIMConfiguration(ctx context.Context, id credbound.UUID) (credbound.SCIMConfiguration, error) {
	row, err := s.queries.GetSCIMConfiguration(ctx, dbID(id))
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
			ID: dbID(configuration.ID), DefaultRole: string(configuration.DefaultRole), TrustDirectoryEmails: configuration.TrustDirectoryEmails,
			GroupRoleMappingsJson: mappings, UpdatedAt: configuration.UpdatedAt, WorkspaceID: dbID(configuration.WorkspaceID),
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
		ID: domainID(row.CredentialID), ConfigurationID: domainID(row.ConfigurationID), Prefix: row.Prefix, Digest: row.Digest,
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
func (s *Store) RevokeSCIMCredential(ctx context.Context, configurationID, id credbound.UUID, revokedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.RevokeSCIMCredential(ctx, db.RevokeSCIMCredentialParams{
			ConfigurationID: dbID(configurationID), ID: dbID(id), RevokedAt: nullableTime(&revokedAt),
		})
		return affected(count, err)
	})
}

// TouchSCIMCredential records a successful use of the credential.
func (s *Store) TouchSCIMCredential(ctx context.Context, id credbound.UUID, usedAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.TouchSCIMCredential(ctx, db.TouchSCIMCredentialParams{ID: dbID(id), LastUsedAt: nullableTime(&usedAt)})
		return affected(count, err)
	})
}

// DisableSCIMConfiguration marks the configuration disabled so its
// credentials stop authenticating.
func (s *Store) DisableSCIMConfiguration(ctx context.Context, id credbound.UUID, disabledAt time.Time, commit credbound.Commit) error {
	return s.mutate(ctx, commit, func(q *db.Queries) error {
		count, err := q.DisableSCIMConfiguration(ctx, db.DisableSCIMConfigurationParams{ID: dbID(id), UpdatedAt: disabledAt})
		if err := affected(count, err); err != nil {
			return err
		}
		return mapError(q.RevokeSCIMCredentials(ctx, db.RevokeSCIMCredentialsParams{ConfigurationID: dbID(id), RevokedAt: nullableTime(&disabledAt)}))
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
func (s *Store) SCIMUser(ctx context.Context, configurationID, id credbound.UUID) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUser(ctx, db.GetSCIMUserParams{ConfigurationID: dbID(configurationID), ID: dbID(id)})
	if err != nil {
		return credbound.SCIMUser{}, mapError(err)
	}
	return scimUserFromRow(row)
}

// SCIMUserByExternalID resolves the configuration's SCIM user by its
// directory external ID.
func (s *Store) SCIMUserByExternalID(ctx context.Context, configurationID credbound.UUID, externalID string) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUserByExternalID(ctx, db.GetSCIMUserByExternalIDParams{ConfigurationID: dbID(configurationID), ExternalID: nullableString(externalID)})
	if err != nil {
		return credbound.SCIMUser{}, mapError(err)
	}
	return scimUserFromRow(row)
}

// SCIMUserByUserName resolves the configuration's SCIM user by normalized
// userName.
func (s *Store) SCIMUserByUserName(ctx context.Context, configurationID credbound.UUID, userName string) (credbound.SCIMUser, error) {
	row, err := s.queries.GetSCIMUserByUserName(ctx, db.GetSCIMUserByUserNameParams{ConfigurationID: dbID(configurationID), NormalizedUserName: strings.ToLower(strings.TrimSpace(userName))})
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
			ConfigurationID: dbID(link.ConfigurationID), ID: dbID(link.ID), ExternalID: nullableString(link.ExternalID),
			NormalizedUserName: link.UserName, DisplayName: link.DisplayName, EmailsJson: emails, ProfileJson: profile, Active: link.Active,
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
				UserID: dbID(link.UserID), WorkspaceID: dbID(membership.WorkspaceID), RevokedAt: nullableTime(&link.UpdatedAt),
			}))
		}
		return nil
	})
}

// SCIMUsers streams the configuration's users matching the filter, newest
// first, as one cursor page.
func (s *Store) SCIMUsers(ctx context.Context, configurationID credbound.UUID, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMUser], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMUser], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		query, args, err := scimUserListQuery(configurationID, filter, cursor, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		rows, err := s.query(streamCtx, query, args...)
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
			ID: dbID(group.ID), ConfigurationID: dbID(group.ConfigurationID), ExternalID: nullableString(group.ExternalID), DisplayName: group.DisplayName,
			MemberIdsJson: members, CreatedAt: group.CreatedAt, UpdatedAt: group.UpdatedAt, DeletedAt: nullableTime(group.DeletedAt),
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
func (s *Store) SCIMGroup(ctx context.Context, configurationID, id credbound.UUID) (credbound.SCIMGroup, error) {
	row, err := s.queries.GetSCIMGroup(ctx, db.GetSCIMGroupParams{ConfigurationID: dbID(configurationID), ID: dbID(id)})
	if err != nil {
		return credbound.SCIMGroup{}, mapError(err)
	}
	return scimGroupFromRow(row)
}

// SCIMGroupByExternalID resolves the configuration's group by its directory
// external ID.
func (s *Store) SCIMGroupByExternalID(ctx context.Context, configurationID credbound.UUID, externalID string) (credbound.SCIMGroup, error) {
	row, err := s.queries.GetSCIMGroupByExternalID(ctx, db.GetSCIMGroupByExternalIDParams{ConfigurationID: dbID(configurationID), ExternalID: nullableString(externalID)})
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
			ConfigurationID: dbID(group.ConfigurationID), ID: dbID(group.ID), DeletedAt: nullableTime(group.DeletedAt), UpdatedAt: group.UpdatedAt,
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
func (s *Store) SCIMGroups(ctx context.Context, configurationID credbound.UUID, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMGroup], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMGroup], error) bool) {
		streamCtx, cancel := context.WithTimeout(ctx, s.streamTimeout)
		defer cancel()
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		query, args, err := scimGroupListQuery(configurationID, filter, cursor, page.Limit+1)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		rows, err := s.query(streamCtx, query, args...)
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
		ID: dbID(value.ID), WorkspaceID: dbID(value.WorkspaceID), Enabled: value.Enabled, DefaultRole: string(value.DefaultRole),
		TrustDirectoryEmails: value.TrustDirectoryEmails, GroupRoleMappingsJson: mappings, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}))
}

func insertSCIMCredential(ctx context.Context, q *db.Queries, value credbound.SCIMCredential) error {
	return mapError(q.InsertSCIMCredential(ctx, db.InsertSCIMCredentialParams{
		ID: dbID(value.ID), ConfigurationID: dbID(value.ConfigurationID), Prefix: value.Prefix, Digest: value.Digest, CreatedAt: value.CreatedAt,
		ExpiresAt: nullableTime(value.ExpiresAt), LastUsedAt: nullableTime(value.LastUsedAt), RevokedAt: nullableTime(value.RevokedAt),
	}))
}

func insertSCIMUser(ctx context.Context, q *db.Queries, value credbound.SCIMUser) error {
	emails, profile, err := encodeSCIMUserJSON(value)
	if err != nil {
		return err
	}
	return mapError(q.InsertSCIMUser(ctx, db.InsertSCIMUserParams{
		ID: dbID(value.ID), ConfigurationID: dbID(value.ConfigurationID), UserID: dbID(value.UserID), ExternalID: nullableString(value.ExternalID),
		NormalizedUserName: value.UserName, DisplayName: value.DisplayName, EmailsJson: emails, ProfileJson: profile, Active: value.Active,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, DeprovisionedAt: nullableTime(value.DeprovisionedAt),
	}))
}

func scimConfigurationFromRow(row db.CredboundScimConfiguration) (credbound.SCIMConfiguration, error) {
	return decodeSCIMConfiguration(domainID(row.ID), domainID(row.WorkspaceID), row.Enabled, row.DefaultRole, row.TrustDirectoryEmails, row.GroupRoleMappingsJson, row.CreatedAt, row.UpdatedAt)
}

func scimConfigurationFromCredentialRow(row db.GetSCIMConfigurationByCredentialPrefixRow) (credbound.SCIMConfiguration, error) {
	return decodeSCIMConfiguration(domainID(row.ID), domainID(row.WorkspaceID), row.Enabled, row.DefaultRole, row.TrustDirectoryEmails, row.GroupRoleMappingsJson, row.CreatedAt, row.UpdatedAt)
}

func decodeSCIMConfiguration(id, workspaceID credbound.UUID, enabled bool, defaultRole string, trust bool, mappingsJSON []byte, createdAt, updatedAt time.Time) (credbound.SCIMConfiguration, error) {
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
	return decodeSCIMUser(domainID(row.ID), domainID(row.ConfigurationID), domainID(row.UserID), row.ExternalID.String, row.NormalizedUserName, row.DisplayName, row.EmailsJson, row.ProfileJson, row.Active, row.CreatedAt, row.UpdatedAt, row.DeprovisionedAt)
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

func decodeSCIMUser(id, configurationID, userID credbound.UUID, externalID, userName, displayName string, emailsJSON, profileJSON []byte, active bool, createdAt, updatedAt time.Time, deprovisioned sql.NullTime) (credbound.SCIMUser, error) {
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
	return decodeSCIMGroup(domainID(row.ID), domainID(row.ConfigurationID), row.ExternalID.String, row.DisplayName, row.MemberIdsJson, row.CreatedAt, row.UpdatedAt, row.DeletedAt)
}

func decodeSCIMGroup(id, configurationID credbound.UUID, externalID, displayName string, membersJSON []byte, createdAt, updatedAt time.Time, deleted sql.NullTime) (credbound.SCIMGroup, error) {
	var members []credbound.UUID
	if err := json.Unmarshal(membersJSON, &members); err != nil {
		return credbound.SCIMGroup{}, err
	}
	return credbound.SCIMGroup{
		ID: id, ConfigurationID: configurationID, ExternalID: externalID, DisplayName: displayName, MemberIDs: members,
		CreatedAt: createdAt, UpdatedAt: updatedAt, DeletedAt: timePointer(deleted),
	}, nil
}

func scanSCIMUser(row scanner) (credbound.SCIMUser, error) {
	var id, configurationID, userID credbound.UUID
	var userName, displayName string
	var emails, profile []byte
	var external sql.NullString
	var active bool
	var createdAt, updatedAt time.Time
	var deprovisioned sql.NullTime
	if err := row.Scan(&id, &configurationID, &userID, &external, &userName, &displayName, &emails, &profile, &active, &createdAt, &updatedAt, &deprovisioned); err != nil {
		return credbound.SCIMUser{}, err
	}
	return decodeSCIMUser(id, configurationID, userID, external.String, userName, displayName, emails, profile, active, createdAt, updatedAt, deprovisioned)
}

func scanSCIMGroup(row scanner) (credbound.SCIMGroup, error) {
	var id, configurationID credbound.UUID
	var displayName string
	var members []byte
	var external sql.NullString
	var createdAt, updatedAt time.Time
	var deleted sql.NullTime
	if err := row.Scan(&id, &configurationID, &external, &displayName, &members, &createdAt, &updatedAt, &deleted); err != nil {
		return credbound.SCIMGroup{}, err
	}
	return decodeSCIMGroup(id, configurationID, external.String, displayName, members, createdAt, updatedAt, deleted)
}

// scimUserListQuery assembles the SCIM user listing: the filter comes from the
// protocol and is optional, as is the cursor, so both are numbered as they are
// added rather than guarded in SQL.
func scimUserListQuery(configurationID credbound.UUID, filter credbound.SCIMFilter, after cursor, limit int) (string, []any, error) {
	query := `SELECT id, configuration_id, user_id, external_id, normalized_user_name, display_name, emails_json, profile_json, active, created_at, updated_at, deprovisioned_at
FROM credbound.scim_users WHERE configuration_id = $1::uuid AND deprovisioned_at IS NULL`
	args := []any{configurationID}
	add := func(clause string, value any) {
		args = append(args, value)
		query += fmt.Sprintf(clause, len(args))
	}
	switch filter.Attribute {
	case "":
	case "id":
		// The filter value reaches us from an IdP, so it may not be a UUID at
		// all. Comparing it against the uuid column would fail the whole
		// listing; a caller filtering on a malformed id gets an empty page,
		// which is what "no such resource" means in SCIM.
		if !validUUID(filter.Value) {
			return query + " AND false", args, nil
		}
		add(" AND id = $%d::uuid", filter.Value)
	case "externalId":
		add(" AND external_id = $%d", filter.Value)
	case "userName":
		add(" AND normalized_user_name = $%d", strings.ToLower(strings.TrimSpace(filter.Value)))
	case "emails.value":
		// emails_json is jsonb, so the containment operator can use a GIN index
		// on it, unlike an equality test over an unnested array.
		add(` AND emails_json @> jsonb_build_array(jsonb_build_object('value', $%d::text))`, strings.ToLower(strings.TrimSpace(filter.Value)))
	case "active":
		value := false
		if strings.EqualFold(filter.Value, "true") {
			value = true
		} else if !strings.EqualFold(filter.Value, "false") {
			return "", nil, fmt.Errorf("%w: invalid active filter", credbound.ErrInvalidInput)
		}
		add(" AND active = $%d", value)
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM user filter", credbound.ErrInvalidInput)
	}
	if after.ID != (credbound.UUID{}) {
		args = append(args, after.Time, after.ID)
		query += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, limit)
	return query + fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", len(args)), args, nil
}

// scimGroupListQuery is scimUserListQuery for groups; see it for the reasoning.
func scimGroupListQuery(configurationID credbound.UUID, filter credbound.SCIMFilter, after cursor, limit int) (string, []any, error) {
	query := `SELECT id, configuration_id, external_id, display_name, member_ids_json, created_at, updated_at, deleted_at
FROM credbound.scim_groups WHERE configuration_id = $1::uuid AND deleted_at IS NULL`
	args := []any{configurationID}
	add := func(clause string, value any) {
		args = append(args, value)
		query += fmt.Sprintf(clause, len(args))
	}
	switch filter.Attribute {
	case "":
	case "id":
		// See scimUserListQuery: a malformed id is an empty page, not an error.
		if !validUUID(filter.Value) {
			return query + " AND false", args, nil
		}
		add(" AND id = $%d::uuid", filter.Value)
	case "externalId":
		add(" AND external_id = $%d", filter.Value)
	case "displayName":
		add(" AND display_name = $%d", filter.Value)
	default:
		return "", nil, fmt.Errorf("%w: unsupported SCIM group filter", credbound.ErrInvalidInput)
	}
	if after.ID != (credbound.UUID{}) {
		args = append(args, after.Time, after.ID)
		query += fmt.Sprintf(" AND (created_at, id) < ($%d, $%d::uuid)", len(args)-1, len(args))
	}
	args = append(args, limit)
	return query + fmt.Sprintf(" ORDER BY created_at DESC, id DESC LIMIT $%d", len(args)), args, nil
}

// SCIMConfigurations streams the workspace's provisioning domains, oldest
// first.
func (s *Store) SCIMConfigurations(ctx context.Context, workspaceID credbound.UUID) iter.Seq2[credbound.SCIMConfiguration, error] {
	return func(yield func(credbound.SCIMConfiguration, error) bool) {
		rows, err := s.queries.ListSCIMConfigurationsByWorkspace(ctx, dbID(workspaceID))
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
func (s *Store) SCIMCredentials(ctx context.Context, configurationID credbound.UUID) iter.Seq2[credbound.SCIMCredential, error] {
	return func(yield func(credbound.SCIMCredential, error) bool) {
		rows, err := s.queries.ListSCIMCredentials(ctx, dbID(configurationID))
		if err != nil {
			yield(credbound.SCIMCredential{}, mapError(err))
			return
		}
		for _, row := range rows {
			value := credbound.SCIMCredential{
				ID: domainID(row.ID), ConfigurationID: domainID(row.ConfigurationID), Prefix: row.Prefix,
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
func (s *Store) SCIMUsersByUser(ctx context.Context, userID credbound.UUID) iter.Seq2[credbound.SCIMUser, error] {
	return func(yield func(credbound.SCIMUser, error) bool) {
		rows, err := s.queries.ListSCIMUsersForUser(ctx, dbID(userID))
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
