package memory

import (
	"context"
	"encoding/json"
	"iter"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/deepteams/credbound"
)

// CreateSCIMConfiguration stores a workspace's SCIM configuration together
// with its first bearer credential.
func (s *Store) CreateSCIMConfiguration(ctx context.Context, configuration credbound.SCIMConfiguration, credential credbound.SCIMCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workspaces[configuration.WorkspaceID]; !ok {
		return credbound.ErrNotFound
	}
	if _, exists := s.scimConfigurations[configuration.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.scimCredentialKeys[credential.Prefix]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.scimConfigurations[configuration.ID] = cloneSCIMConfiguration(configuration)
	s.scimCredentials[credential.ID] = cloneSCIMCredential(credential)
	s.scimCredentialKeys[credential.Prefix] = credential.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMConfiguration returns the configuration with the given ID.
func (s *Store) SCIMConfiguration(ctx context.Context, id string) (credbound.SCIMConfiguration, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMConfiguration{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	configuration, ok := s.scimConfigurations[id]
	if !ok {
		return credbound.SCIMConfiguration{}, credbound.ErrNotFound
	}
	return cloneSCIMConfiguration(configuration), nil
}

// UpdateSCIMConfiguration persists the configuration's settings and applies
// the recomputed memberships in the same commit.
func (s *Store) UpdateSCIMConfiguration(ctx context.Context, configuration credbound.SCIMConfiguration, memberships []credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.scimConfigurations[configuration.ID]
	if !ok || current.WorkspaceID != configuration.WorkspaceID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.scimConfigurations[configuration.ID] = cloneSCIMConfiguration(configuration)
	for _, membership := range memberships {
		if s.memberships[membership.WorkspaceID] == nil {
			s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
		}
		s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMConfigurationByCredentialPrefix resolves the configuration and
// credential addressed by a bearer token's lookup prefix.
func (s *Store) SCIMConfigurationByCredentialPrefix(ctx context.Context, prefix string) (credbound.SCIMConfiguration, credbound.SCIMCredential, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	credentialID, ok := s.scimCredentialKeys[prefix]
	if !ok {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, credbound.ErrNotFound
	}
	credential := s.scimCredentials[credentialID]
	configuration, ok := s.scimConfigurations[credential.ConfigurationID]
	if !ok {
		return credbound.SCIMConfiguration{}, credbound.SCIMCredential{}, credbound.ErrNotFound
	}
	return cloneSCIMConfiguration(configuration), cloneSCIMCredential(credential), nil
}

// SaveSCIMCredential stores an additional bearer credential for a
// configuration.
func (s *Store) SaveSCIMCredential(ctx context.Context, credential credbound.SCIMCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scimConfigurations[credential.ConfigurationID]; !ok {
		return credbound.ErrNotFound
	}
	if _, exists := s.scimCredentials[credential.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.scimCredentialKeys[credential.Prefix]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.scimCredentials[credential.ID] = cloneSCIMCredential(credential)
	s.scimCredentialKeys[credential.Prefix] = credential.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeSCIMCredential marks the configuration's credential revoked.
func (s *Store) RevokeSCIMCredential(ctx context.Context, configurationID, id string, revokedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.scimCredentials[id]
	if !ok || credential.ConfigurationID != configurationID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	credential.RevokedAt = cloneTime(&revokedAt)
	s.scimCredentials[id] = credential
	return s.finishCommitLocked(ctx, commit, previous)
}

// TouchSCIMCredential records a successful use of the credential.
func (s *Store) TouchSCIMCredential(ctx context.Context, id string, usedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.scimCredentials[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	credential.LastUsedAt = cloneTime(&usedAt)
	s.scimCredentials[id] = credential
	return s.finishCommitLocked(ctx, commit, previous)
}

// DisableSCIMConfiguration marks the configuration disabled so its
// credentials stop authenticating.
func (s *Store) DisableSCIMConfiguration(ctx context.Context, id string, disabledAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	configuration, ok := s.scimConfigurations[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	configuration.Enabled, configuration.UpdatedAt = false, disabledAt
	s.scimConfigurations[id] = configuration
	for credentialID, credential := range s.scimCredentials {
		if credential.ConfigurationID == id && credential.RevokedAt == nil {
			credential.RevokedAt = cloneTime(&disabledAt)
			s.scimCredentials[credentialID] = credential
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateSCIMUser atomically creates the Credbound user, email and membership
// for a directory user and links them to the SCIM record.
func (s *Store) CreateSCIMUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, membership credbound.Membership, link credbound.SCIMUser, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	configuration, ok := s.scimConfigurations[link.ConfigurationID]
	if !ok || configuration.WorkspaceID != membership.WorkspaceID {
		return credbound.ErrNotFound
	}
	if _, exists := s.users[user.ID]; exists || s.scimUserConflictLocked(link, "") {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.users[user.ID] = cloneUser(user)
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	if email.VerifiedAt != nil {
		s.emails[email.Address] = user.ID
	}
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	s.memberships[membership.WorkspaceID][user.ID] = normalizeMembership(membership)
	s.putSCIMUserLocked(link)
	return s.finishCommitLocked(ctx, commit, previous)
}

// AdoptSCIMUser links a directory user to an existing Credbound account,
// installing the membership in the same commit.
func (s *Store) AdoptSCIMUser(ctx context.Context, membership credbound.Membership, link credbound.SCIMUser, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	configuration, ok := s.scimConfigurations[link.ConfigurationID]
	if !ok || configuration.WorkspaceID != membership.WorkspaceID {
		return credbound.ErrNotFound
	}
	if _, ok := s.users[link.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.memberships[membership.WorkspaceID][membership.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if s.scimUserConflictLocked(link, "") {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	s.putSCIMUserLocked(link)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMUser returns the configuration's SCIM user with the given ID.
func (s *Store) SCIMUser(ctx context.Context, configurationID, id string) (credbound.SCIMUser, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMUser{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	link, ok := s.scimUsers[id]
	if !ok || link.ConfigurationID != configurationID {
		return credbound.SCIMUser{}, credbound.ErrNotFound
	}
	return cloneSCIMUser(link), nil
}

// SCIMUserByExternalID resolves the configuration's SCIM user by its
// directory external ID.
func (s *Store) SCIMUserByExternalID(ctx context.Context, configurationID, externalID string) (credbound.SCIMUser, error) {
	return s.scimUserByKey(ctx, s.scimExternalIDs, scimKey(configurationID, strings.TrimSpace(externalID)))
}

// SCIMUserByUserName resolves the configuration's SCIM user by normalized
// userName.
func (s *Store) SCIMUserByUserName(ctx context.Context, configurationID, userName string) (credbound.SCIMUser, error) {
	return s.scimUserByKey(ctx, s.scimUserNames, scimKey(configurationID, strings.ToLower(strings.TrimSpace(userName))))
}

func (s *Store) scimUserByKey(ctx context.Context, index map[string]string, key string) (credbound.SCIMUser, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMUser{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := index[key]
	if !ok {
		return credbound.SCIMUser{}, credbound.ErrNotFound
	}
	return cloneSCIMUser(s.scimUsers[id]), nil
}

// UpdateSCIMUser persists the directory record and membership change,
// optionally revoking the user's workspace PATs on deactivation.
func (s *Store) UpdateSCIMUser(ctx context.Context, link credbound.SCIMUser, membership credbound.Membership, revokeWorkspacePATs bool, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.scimUsers[link.ID]
	if !ok || current.ConfigurationID != link.ConfigurationID || current.UserID != link.UserID {
		return credbound.ErrNotFound
	}
	if s.scimUserConflictLocked(link, link.ID) {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.deleteSCIMUserIndexesLocked(current)
	s.putSCIMUserLocked(link)
	s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	if revokeWorkspacePATs {
		for id, pat := range s.pats {
			if pat.UserID == link.UserID && pat.WorkspaceID == membership.WorkspaceID && pat.RevokedAt == nil {
				pat.RevokedAt = cloneTime(&link.UpdatedAt)
				s.pats[id] = pat
			}
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMUsers streams the configuration's users matching the filter, newest
// first, as one cursor page.
func (s *Store) SCIMUsers(ctx context.Context, configurationID string, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMUser], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMUser], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SCIMUser]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.SCIMUser, 0)
		for _, link := range s.scimUsers {
			if link.ConfigurationID == configurationID && link.DeprovisionedAt == nil && afterCursor(link.CreatedAt, link.ID, cursor) && matchSCIMUser(link, filter) {
				values = append(values, cloneSCIMUser(link))
			}
		}
		s.mu.RUnlock()
		yieldSCIMPage(ctx, values, page, func(value credbound.SCIMUser) time.Time { return value.CreatedAt }, func(value credbound.SCIMUser) string { return value.ID }, yield)
	}
}

// UpsertSCIMGroup inserts or replaces a directory group and applies the
// recomputed memberships in the same commit.
func (s *Store) UpsertSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.scimConfigurations[group.ConfigurationID]; !ok {
		return credbound.ErrNotFound
	}
	current, exists := s.scimGroups[group.ID]
	if exists && current.ConfigurationID != group.ConfigurationID {
		return credbound.ErrConflict
	}
	if group.ExternalID != "" {
		if id, duplicate := s.scimGroupExternal[scimKey(group.ConfigurationID, group.ExternalID)]; duplicate && id != group.ID {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if exists && current.ExternalID != "" {
		delete(s.scimGroupExternal, scimKey(current.ConfigurationID, current.ExternalID))
	}
	s.scimGroups[group.ID] = cloneSCIMGroup(group)
	if group.ExternalID != "" {
		s.scimGroupExternal[scimKey(group.ConfigurationID, group.ExternalID)] = group.ID
	}
	for _, membership := range memberships {
		s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMGroup returns the configuration's group with the given ID.
func (s *Store) SCIMGroup(ctx context.Context, configurationID, id string) (credbound.SCIMGroup, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMGroup{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.scimGroups[id]
	if !ok || group.ConfigurationID != configurationID || group.DeletedAt != nil {
		return credbound.SCIMGroup{}, credbound.ErrNotFound
	}
	return cloneSCIMGroup(group), nil
}

// SCIMGroupByExternalID resolves the configuration's group by its directory
// external ID.
func (s *Store) SCIMGroupByExternalID(ctx context.Context, configurationID, externalID string) (credbound.SCIMGroup, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SCIMGroup{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.scimGroupExternal[scimKey(configurationID, strings.TrimSpace(externalID))]
	if !ok {
		return credbound.SCIMGroup{}, credbound.ErrNotFound
	}
	group := s.scimGroups[id]
	if group.DeletedAt != nil {
		return credbound.SCIMGroup{}, credbound.ErrNotFound
	}
	return cloneSCIMGroup(group), nil
}

// DeleteSCIMGroup soft-deletes the group and applies the recomputed
// memberships in the same commit.
func (s *Store) DeleteSCIMGroup(ctx context.Context, group credbound.SCIMGroup, memberships []credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.scimGroups[group.ID]
	if !ok || current.ConfigurationID != group.ConfigurationID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.scimGroups[group.ID] = cloneSCIMGroup(group)
	if current.ExternalID != "" {
		delete(s.scimGroupExternal, scimKey(current.ConfigurationID, current.ExternalID))
	}
	for _, membership := range memberships {
		s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// SCIMGroups streams the configuration's groups matching the filter, newest
// first, as one cursor page.
func (s *Store) SCIMGroups(ctx context.Context, configurationID string, filter credbound.SCIMFilter, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SCIMGroup], error] {
	return func(yield func(credbound.PageEvent[credbound.SCIMGroup], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SCIMGroup]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.SCIMGroup, 0)
		for _, group := range s.scimGroups {
			if group.ConfigurationID == configurationID && group.DeletedAt == nil && afterCursor(group.CreatedAt, group.ID, cursor) && matchSCIMGroup(group, filter) {
				values = append(values, cloneSCIMGroup(group))
			}
		}
		s.mu.RUnlock()
		yieldSCIMPage(ctx, values, page, func(value credbound.SCIMGroup) time.Time { return value.CreatedAt }, func(value credbound.SCIMGroup) string { return value.ID }, yield)
	}
}

func matchSCIMGroup(group credbound.SCIMGroup, filter credbound.SCIMFilter) bool {
	switch filter.Attribute {
	case "":
		return true
	case "id":
		return group.ID == filter.Value
	case "externalId":
		return group.ExternalID == filter.Value
	case "displayName":
		return group.DisplayName == filter.Value
	default:
		return false
	}
}

func (s *Store) scimUserConflictLocked(link credbound.SCIMUser, exceptID string) bool {
	if id, ok := s.scimUserNames[scimKey(link.ConfigurationID, link.UserName)]; ok && id != exceptID {
		return true
	}
	if link.ExternalID != "" {
		if id, ok := s.scimExternalIDs[scimKey(link.ConfigurationID, link.ExternalID)]; ok && id != exceptID {
			return true
		}
	}
	return false
}

func (s *Store) putSCIMUserLocked(link credbound.SCIMUser) {
	s.scimUsers[link.ID] = cloneSCIMUser(link)
	s.scimUserNames[scimKey(link.ConfigurationID, link.UserName)] = link.ID
	if link.ExternalID != "" {
		s.scimExternalIDs[scimKey(link.ConfigurationID, link.ExternalID)] = link.ID
	}
}

func (s *Store) deleteSCIMUserIndexesLocked(link credbound.SCIMUser) {
	delete(s.scimUserNames, scimKey(link.ConfigurationID, link.UserName))
	if link.ExternalID != "" {
		delete(s.scimExternalIDs, scimKey(link.ConfigurationID, link.ExternalID))
	}
}

func scimKey(configurationID, value string) string { return configurationID + "\x00" + value }

func matchSCIMUser(link credbound.SCIMUser, filter credbound.SCIMFilter) bool {
	if filter.Attribute == "" {
		return true
	}
	switch filter.Attribute {
	case "id":
		return link.ID == filter.Value
	case "externalId":
		return link.ExternalID == filter.Value
	case "userName":
		return link.UserName == strings.ToLower(strings.TrimSpace(filter.Value))
	case "active":
		return (strings.EqualFold(filter.Value, "true") && link.Active) || (strings.EqualFold(filter.Value, "false") && !link.Active)
	case "emails.value":
		value := strings.ToLower(strings.TrimSpace(filter.Value))
		return slices.ContainsFunc(link.Emails, func(email credbound.SCIMEmail) bool { return email.Value == value })
	default:
		return false
	}
}

func yieldSCIMPage[T any](ctx context.Context, values []T, page credbound.PageRequest, created func(T) time.Time, id func(T) string, yield func(credbound.PageEvent[T], error) bool) {
	sort.Slice(values, func(i, j int) bool {
		return newer(created(values[i]), id(values[i]), created(values[j]), id(values[j]))
	})
	hasMore := len(values) > page.Limit
	if hasMore {
		values = values[:page.Limit]
	}
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[T]{}, err)
			return
		}
		if !yield(credbound.ItemEvent(value), nil) {
			return
		}
	}
	end := credbound.PageEnd{HasMore: hasMore}
	if hasMore && len(values) > 0 {
		last := values[len(values)-1]
		end.NextCursor = encodeCursor(created(last), id(last))
	}
	yield(credbound.EndEvent[T](end), nil)
}

func cloneSCIMConfiguration(value credbound.SCIMConfiguration) credbound.SCIMConfiguration {
	value.GroupRoleMappings = slices.Clone(value.GroupRoleMappings)
	return value
}

func cloneSCIMCredential(value credbound.SCIMCredential) credbound.SCIMCredential {
	value.Digest = slices.Clone(value.Digest)
	value.ExpiresAt, value.LastUsedAt, value.RevokedAt = cloneTime(value.ExpiresAt), cloneTime(value.LastUsedAt), cloneTime(value.RevokedAt)
	return value
}

func cloneSCIMUser(value credbound.SCIMUser) credbound.SCIMUser {
	value.Schemas = slices.Clone(value.Schemas)
	value.Emails = slices.Clone(value.Emails)
	if value.Attributes != nil {
		attributes := make(map[string]json.RawMessage, len(value.Attributes))
		for key, raw := range value.Attributes {
			attributes[key] = slices.Clone(raw)
		}
		value.Attributes = attributes
	}
	value.DeprovisionedAt = cloneTime(value.DeprovisionedAt)
	return value
}

func cloneSCIMGroup(value credbound.SCIMGroup) credbound.SCIMGroup {
	value.MemberIDs = slices.Clone(value.MemberIDs)
	value.DeletedAt = cloneTime(value.DeletedAt)
	return value
}
