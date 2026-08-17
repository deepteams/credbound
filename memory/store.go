// Package memory provides an in-memory implementation of every Credbound
// persistence port — Store plus the optional SessionStore, SignupStore,
// DomainStore, SCIMStore and OAuthStore capabilities — including the
// hash-chained audit log and its atomic commit semantics.
//
// It exists for tests, examples and prototypes: nothing is persisted beyond
// the process, so it must never back a production deployment. Wire it into
// credbound.Config.Store:
//
//	store := memory.New()
//
// The store is safe for concurrent use. Method semantics, sentinel errors
// and pagination behavior are specified on the credbound port interfaces.
package memory

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deepteams/credbound"
)

// Store keeps all Credbound state in process-local maps guarded by one
// RWMutex. Reads return defensive copies, and every mutation commits its
// audit event atomically with the change, mirroring the SQL stores. The
// contract for each method is documented on the credbound port interfaces.
type Store struct {
	mu                 sync.RWMutex
	users              map[string]credbound.User
	emails             map[string]string
	emailAddresses     map[string]credbound.EmailAddress
	emailIDs           map[string]string
	emailVerifications map[string]credbound.EmailVerificationCredential
	passwords          map[string]credbound.PasswordCredential
	workspaces         map[string]credbound.Workspace
	memberships        map[string]map[string]credbound.Membership
	admins             map[string]credbound.InstanceAdministrator
	ssoIdentities      map[string]credbound.SSOIdentity
	ssoKeys            map[string]string
	totp               map[string]credbound.TOTPFactor
	recovery           map[string][]credbound.RecoveryCode
	passkeys           map[string]map[string]credbound.Passkey
	pats               map[string]credbound.PAT
	patPrefixes        map[string]string
	sessions           map[string]credbound.Session
	domains            map[string]credbound.WorkspaceDomain
	domainNames        map[string]string
	scimConfigurations map[string]credbound.SCIMConfiguration
	scimCredentials    map[string]credbound.SCIMCredential
	scimCredentialKeys map[string]string
	scimUsers          map[string]credbound.SCIMUser
	scimUserNames      map[string]string
	scimExternalIDs    map[string]string
	scimGroups         map[string]credbound.SCIMGroup
	scimGroupExternal  map[string]string
	oauthIssuers       map[string]credbound.OAuthIssuer
	oauthIssuerURLs    map[string]string
	oauthResources     map[string]credbound.OAuthProtectedResource
	oauthResourceURIs  map[string]string
	oauthClients       map[string]credbound.OAuthClient
	oauthClientKeys    map[string]string
	oauthInitialTokens map[string]credbound.OAuthInitialAccessToken
	oauthInitialKeys   map[string]string
	oauthGrants        map[string]credbound.OAuthGrant
	oauthCodes         map[string]credbound.OAuthAuthorizationCode
	oauthCodeKeys      map[string]string
	oauthAccessTokens  map[string]credbound.OAuthAccessToken
	oauthAccessKeys    map[string]string
	oauthRefreshTokens map[string]credbound.OAuthRefreshToken
	oauthRefreshKeys   map[string]string
	throttles          map[string]credbound.LoginThrottle
	passwordResets     map[string]credbound.PasswordResetCredential
	emailAuths         map[string]credbound.EmailAuthenticationCredential
	invitations        map[string]credbound.WorkspaceInvitation
	audits             []credbound.AuditEvent
	auditIDs           map[string]struct{}
	auditSequence      int64
	auditHead          []byte
	auditFailure       error
}

// Tx is the in-memory transaction capability. It intentionally exposes no
// application data handle; cross-table integrations are exercised with a SQL
// store. Active becomes false immediately after the hook returns.
type Tx struct {
	audit  credbound.AuditEvent
	active atomic.Bool
}

func newTx(audit credbound.AuditEvent) *Tx {
	tx := &Tx{audit: audit}
	tx.active.Store(true)
	return tx
}

// Kind reports credbound.StoreMemory.
func (t *Tx) Kind() credbound.StoreKind { return credbound.StoreMemory }

// Audit returns the audit event being committed with this transaction.
func (t *Tx) Audit() credbound.AuditEvent { return t.audit }

// Active reports whether the hook callback owning this handle is still
// running; it is false once the commit has completed.
func (t *Tx) Active() bool { return t != nil && t.active.Load() }

func (t *Tx) close() {
	if t != nil {
		t.active.Store(false)
	}
}

// TxFrom converts a generic Credbound transaction into the in-memory
// capability. It returns false for another store's transaction or a handle
// whose hook callback has already returned.
func TxFrom(tx credbound.Tx) (*Tx, bool) {
	handle, ok := tx.(*Tx)
	if !ok || !handle.Active() {
		return nil, false
	}
	return handle, true
}

// New returns an empty Store ready to be passed as credbound.Config.Store.
func New() *Store {
	return &Store{
		users: make(map[string]credbound.User), emails: make(map[string]string),
		emailAddresses: make(map[string]credbound.EmailAddress), emailIDs: make(map[string]string),
		emailVerifications: make(map[string]credbound.EmailVerificationCredential),
		passwords:          make(map[string]credbound.PasswordCredential), workspaces: make(map[string]credbound.Workspace),
		memberships: make(map[string]map[string]credbound.Membership), admins: make(map[string]credbound.InstanceAdministrator),
		totp: make(map[string]credbound.TOTPFactor), recovery: make(map[string][]credbound.RecoveryCode),
		passkeys: make(map[string]map[string]credbound.Passkey), pats: make(map[string]credbound.PAT),
		patPrefixes: make(map[string]string), sessions: make(map[string]credbound.Session),
		domains: make(map[string]credbound.WorkspaceDomain), domainNames: make(map[string]string), auditIDs: make(map[string]struct{}),
		auditHead: make([]byte, 32), throttles: make(map[string]credbound.LoginThrottle),
		passwordResets: make(map[string]credbound.PasswordResetCredential),
		emailAuths:     make(map[string]credbound.EmailAuthenticationCredential),
		invitations:    make(map[string]credbound.WorkspaceInvitation),
		ssoIdentities:  make(map[string]credbound.SSOIdentity), ssoKeys: make(map[string]string),
		scimConfigurations: make(map[string]credbound.SCIMConfiguration),
		scimCredentials:    make(map[string]credbound.SCIMCredential), scimCredentialKeys: make(map[string]string),
		scimUsers: make(map[string]credbound.SCIMUser), scimUserNames: make(map[string]string), scimExternalIDs: make(map[string]string),
		scimGroups: make(map[string]credbound.SCIMGroup), scimGroupExternal: make(map[string]string),
		oauthIssuers: make(map[string]credbound.OAuthIssuer), oauthIssuerURLs: make(map[string]string),
		oauthResources: make(map[string]credbound.OAuthProtectedResource), oauthResourceURIs: make(map[string]string),
		oauthClients: make(map[string]credbound.OAuthClient), oauthClientKeys: make(map[string]string),
		oauthInitialTokens: make(map[string]credbound.OAuthInitialAccessToken), oauthInitialKeys: make(map[string]string),
		oauthGrants: make(map[string]credbound.OAuthGrant), oauthCodes: make(map[string]credbound.OAuthAuthorizationCode), oauthCodeKeys: make(map[string]string),
		oauthAccessTokens: make(map[string]credbound.OAuthAccessToken), oauthAccessKeys: make(map[string]string),
		oauthRefreshTokens: make(map[string]credbound.OAuthRefreshToken), oauthRefreshKeys: make(map[string]string),
	}
}

// SetAuditFailure is intended for fault-injection tests. While set, every
// mutation fails atomically before changing state.
func (s *Store) SetAuditFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditFailure = err
}

// Bootstrap atomically creates the first user with its primary email,
// password, workspace, admin membership and root administrator; once the
// instance is populated it reports credbound.ErrConflict.
func (s *Store) Bootstrap(ctx context.Context, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, workspace credbound.Workspace, membership credbound.Membership, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) != 0 {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.users[user.ID] = cloneUser(user)
	s.emails[email.Address] = user.ID
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	s.passwords[user.ID] = password
	s.workspaces[workspace.ID] = workspace
	s.memberships[workspace.ID] = map[string]credbound.Membership{user.ID: normalizeMembership(membership)}
	s.admins[user.ID] = admin
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateUser inserts a user with a primary email, password credential and
// initial membership in an existing workspace; a duplicate user ID or email
// address reports credbound.ErrConflict.
func (s *Store) CreateUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, membership credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.workspaces[membership.WorkspaceID]; !exists {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.users[user.ID] = cloneUser(user)
	s.emails[email.Address] = user.ID
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	s.passwords[user.ID] = password
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	s.memberships[membership.WorkspaceID][user.ID] = normalizeMembership(membership)
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateSignup atomically creates a self-service user, its primary email
// (with the optional pending verification), password credential and fresh
// workspace; an unverified address stays excluded from sign-in lookup until
// VerifyEmail.
func (s *Store) CreateSignup(ctx context.Context, user credbound.User, email credbound.EmailAddress, verification *credbound.EmailVerificationCredential, password credbound.PasswordCredential, workspace credbound.Workspace, membership credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.workspaces[workspace.ID]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.users[user.ID] = cloneUser(user)
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	// Only a verified address joins the sign-in lookup; an unverified primary
	// becomes matchable by UserByEmail through VerifyEmail.
	if email.VerifiedAt != nil {
		s.emails[email.Address] = user.ID
	}
	if verification != nil {
		s.emailVerifications[email.ID] = cloneEmailVerification(*verification)
	}
	s.passwords[user.ID] = password
	s.workspaces[workspace.ID] = cloneWorkspace(workspace)
	s.memberships[workspace.ID] = map[string]credbound.Membership{user.ID: normalizeMembership(membership)}
	return s.finishCommitLocked(ctx, commit, previous)
}

// UserByEmail resolves a user by verified email address.
func (s *Store) UserByEmail(ctx context.Context, email string) (credbound.User, error) {
	if err := ctx.Err(); err != nil {
		return credbound.User{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.emails[email]
	if !ok {
		return credbound.User{}, credbound.ErrNotFound
	}
	return cloneUser(s.users[id]), nil
}

// UserByID returns the user with the given ID.
func (s *Store) UserByID(ctx context.Context, id string) (credbound.User, error) {
	if err := ctx.Err(); err != nil {
		return credbound.User{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return credbound.User{}, credbound.ErrNotFound
	}
	return cloneUser(user), nil
}

// SetUserDisabled enables or disables a user; disabling refuses to orphan
// the last enabled root administrator or a workspace's last active admin
// (credbound.ErrConflict) and revokes the user's tokens and sessions.
func (s *Store) SetUserDisabled(ctx context.Context, userID string, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return credbound.ErrNotFound
	}
	if disabled {
		if admin, root := s.admins[userID]; root && admin.Role == credbound.InstanceRoleRoot {
			enabledRoots := 0
			for id, candidate := range s.admins {
				if candidate.Role == credbound.InstanceRoleRoot && !s.users[id].Disabled {
					enabledRoots++
				}
			}
			if enabledRoots <= 1 {
				return credbound.ErrConflict
			}
		}
		for workspaceID, membership := range s.memberships {
			candidate, ownsWorkspace := membership[userID]
			if !ownsWorkspace || candidate.Role != credbound.RoleAdmin || candidate.Status != credbound.MembershipActive {
				continue
			}
			hasOtherAdmin := false
			for otherUserID, other := range s.memberships[workspaceID] {
				if otherUserID != userID && other.Role == credbound.RoleAdmin && other.Status == credbound.MembershipActive && !s.users[otherUserID].Disabled {
					hasOtherAdmin = true
					break
				}
			}
			if !hasOtherAdmin {
				return credbound.ErrConflict
			}
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	user.Disabled = disabled
	user.UpdatedAt = at
	s.users[userID] = cloneUser(user)
	if disabled {
		s.revokeUserCredentialsLocked(userID, "", at)
		s.revokeUserSessionsLocked(userID, at)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// Users streams all users, newest first, as one cursor page.
func (s *Store) Users(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.User], error] {
	return func(yield func(credbound.PageEvent[credbound.User], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.User]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.User]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.User, 0, len(s.users))
		for _, user := range s.users {
			if afterCursor(user.CreatedAt, user.ID, cursor) {
				values = append(values, cloneUser(user))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.User) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

// PasswordByUserID returns the user's stored password credential.
func (s *Store) PasswordByUserID(ctx context.Context, userID string) (credbound.PasswordCredential, error) {
	if err := ctx.Err(); err != nil {
		return credbound.PasswordCredential{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	password, ok := s.passwords[userID]
	if !ok {
		return credbound.PasswordCredential{}, credbound.ErrNotFound
	}
	return password, nil
}

// ReplacePassword swaps the user's password credential.
func (s *Store) ReplacePassword(ctx context.Context, password credbound.PasswordCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.passwords[password.UserID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.passwords[password.UserID] = password
	return s.finishCommitLocked(ctx, commit, previous)
}

// RecordAuthentication marks a successful login, updating the user's last-
// seen time and clearing any login throttle.
func (s *Store) RecordAuthentication(ctx context.Context, userID string, seenAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.touchLastSeenLocked(userID, seenAt)
	delete(s.throttles, userID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// LoginThrottleByUserID returns the user's current login throttle state.
func (s *Store) LoginThrottleByUserID(ctx context.Context, userID string) (credbound.LoginThrottle, error) {
	if err := ctx.Err(); err != nil {
		return credbound.LoginThrottle{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	throttle, ok := s.throttles[userID]
	if !ok {
		return credbound.LoginThrottle{}, credbound.ErrNotFound
	}
	return cloneThrottle(throttle), nil
}

// RecordLoginFailure counts a failed login (restarting the window after an
// expired lockout) and applies lockedUntil once the failure threshold is
// reached, returning the updated throttle.
func (s *Store) RecordLoginFailure(ctx context.Context, userID string, at time.Time, threshold int64, lockedUntil time.Time, commit credbound.Commit) (credbound.LoginThrottle, error) {
	if err := ctx.Err(); err != nil {
		return credbound.LoginThrottle{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return credbound.LoginThrottle{}, credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return credbound.LoginThrottle{}, err
	}
	throttle := s.throttles[userID]
	if throttle.LockedUntil != nil && !at.Before(*throttle.LockedUntil) {
		// The previous lockout has expired: the failure window restarts.
		throttle = credbound.LoginThrottle{}
	}
	throttle.UserID = userID
	throttle.FailedAttempts++
	throttle.UpdatedAt = at
	if threshold > 0 && throttle.FailedAttempts >= threshold {
		throttle.LockedUntil = cloneTime(&lockedUntil)
	}
	s.throttles[userID] = throttle
	if err := s.finishCommitLocked(ctx, commit, previous); err != nil {
		return credbound.LoginThrottle{}, err
	}
	return cloneThrottle(throttle), nil
}

func cloneThrottle(value credbound.LoginThrottle) credbound.LoginThrottle {
	value.LockedUntil = cloneTime(value.LockedUntil)
	return value
}

func clonePasswordReset(value credbound.PasswordResetCredential) credbound.PasswordResetCredential {
	value.Digest = slices.Clone(value.Digest)
	value.UsedAt = cloneTime(value.UsedAt)
	return value
}

func cloneEmailAuthentication(value credbound.EmailAuthenticationCredential) credbound.EmailAuthenticationCredential {
	value.Digest = slices.Clone(value.Digest)
	value.UsedAt = cloneTime(value.UsedAt)
	return value
}

// CreatePasswordReset stores a single-use password reset credential.
func (s *Store) CreatePasswordReset(ctx context.Context, credential credbound.PasswordResetCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[credential.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if _, exists := s.passwordResets[credential.ID]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.passwordResets[credential.ID] = clonePasswordReset(credential)
	return s.finishCommitLocked(ctx, commit, previous)
}

// PasswordResetByID returns the password reset credential with the given ID.
func (s *Store) PasswordResetByID(ctx context.Context, resetID string) (credbound.PasswordResetCredential, error) {
	if err := ctx.Err(); err != nil {
		return credbound.PasswordResetCredential{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	credential, ok := s.passwordResets[resetID]
	if !ok {
		return credbound.PasswordResetCredential{}, credbound.ErrNotFound
	}
	return clonePasswordReset(credential), nil
}

// CompletePasswordReset consumes the reset and installs the new password,
// revoking the user's other pending resets, tokens, sessions and throttle in
// the same commit; a reused reset reports credbound.ErrConflict.
func (s *Store) CompletePasswordReset(ctx context.Context, resetID string, password credbound.PasswordCredential, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.passwordResets[resetID]
	if !ok {
		return credbound.ErrNotFound
	}
	if credential.UsedAt != nil {
		return credbound.ErrConflict
	}
	if _, ok := s.users[password.UserID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	credential.UsedAt = cloneTime(&at)
	s.passwordResets[resetID] = credential
	for id, other := range s.passwordResets {
		if id != resetID && other.UserID == password.UserID {
			delete(s.passwordResets, id)
		}
	}
	s.passwords[password.UserID] = password
	s.revokeUserCredentialsLocked(password.UserID, "", at)
	s.revokeUserSessionsLocked(password.UserID, at)
	delete(s.throttles, password.UserID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateEmailAuthentication stores a single-use magic-link or email OTP
// credential.
func (s *Store) CreateEmailAuthentication(ctx context.Context, credential credbound.EmailAuthenticationCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[credential.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if _, exists := s.emailAuths[credential.ID]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.emailAuths[credential.ID] = cloneEmailAuthentication(credential)
	return s.finishCommitLocked(ctx, commit, previous)
}

// EmailAuthenticationByID returns the email authentication credential with
// the given token ID.
func (s *Store) EmailAuthenticationByID(ctx context.Context, tokenID string) (credbound.EmailAuthenticationCredential, error) {
	if err := ctx.Err(); err != nil {
		return credbound.EmailAuthenticationCredential{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	credential, ok := s.emailAuths[tokenID]
	if !ok {
		return credbound.EmailAuthenticationCredential{}, credbound.ErrNotFound
	}
	return cloneEmailAuthentication(credential), nil
}

// ConsumeEmailAuthentication marks the user's credential used, updating
// last-seen and clearing the login throttle; reuse reports
// credbound.ErrConflict.
func (s *Store) ConsumeEmailAuthentication(ctx context.Context, tokenID, userID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	credential, ok := s.emailAuths[tokenID]
	if !ok || credential.UserID != userID {
		return credbound.ErrNotFound
	}
	if credential.UsedAt != nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	credential.UsedAt = cloneTime(&at)
	s.emailAuths[tokenID] = credential
	s.touchLastSeenLocked(userID, at)
	delete(s.throttles, userID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SaveEmail adds an additional email address with its pending verification
// credential; a duplicate address reports credbound.ErrConflict.
func (s *Store) SaveEmail(ctx context.Context, email credbound.EmailAddress, verification credbound.EmailVerificationCredential, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[email.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if _, exists := s.emailAddresses[email.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	s.emailVerifications[email.ID] = cloneEmailVerification(verification)
	return s.finishCommitLocked(ctx, commit, previous)
}

// EmailVerificationByID returns the email address and its pending
// verification credential.
func (s *Store) EmailVerificationByID(ctx context.Context, emailID string) (credbound.EmailAddress, credbound.EmailVerificationCredential, error) {
	if err := ctx.Err(); err != nil {
		return credbound.EmailAddress{}, credbound.EmailVerificationCredential{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	email, ok := s.emailAddresses[emailID]
	if !ok {
		return credbound.EmailAddress{}, credbound.EmailVerificationCredential{}, credbound.ErrNotFound
	}
	verification := s.emailVerifications[emailID]
	return cloneEmail(email), cloneEmailVerification(verification), nil
}

// VerifyEmail marks the address verified, makes it usable for sign-in and
// discards the verification credential; an already-verified address reports
// credbound.ErrConflict.
func (s *Store) VerifyEmail(ctx context.Context, emailID string, verifiedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	email, ok := s.emailAddresses[emailID]
	if !ok {
		return credbound.ErrNotFound
	}
	if email.VerifiedAt != nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	email.VerifiedAt = cloneTime(&verifiedAt)
	email.UpdatedAt = verifiedAt
	s.emailAddresses[emailID] = email
	s.emails[email.Address] = email.UserID
	delete(s.emailVerifications, emailID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SetPrimaryEmail promotes a verified address to primary and demotes the
// previous one; an unverified target reports credbound.ErrConflict.
func (s *Store) SetPrimaryEmail(ctx context.Context, userID, emailID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, ok := s.emailAddresses[emailID]
	if !ok || target.UserID != userID {
		return credbound.ErrNotFound
	}
	if target.VerifiedAt == nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	for id, email := range s.emailAddresses {
		if email.UserID == userID && email.Primary {
			email.Primary = false
			email.UpdatedAt = commit.Audit.OccurredAt
			s.emailAddresses[id] = email
		}
	}
	target.Primary = true
	target.UpdatedAt = commit.Audit.OccurredAt
	s.emailAddresses[emailID] = target
	user := s.users[userID]
	user.Email = target.Address
	user.UpdatedAt = commit.Audit.OccurredAt
	s.users[userID] = user
	return s.finishCommitLocked(ctx, commit, previous)
}

// RemoveEmail deletes a non-primary address, refusing to remove the user's
// last verified one (credbound.ErrConflict).
func (s *Store) RemoveEmail(ctx context.Context, userID, emailID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	email, ok := s.emailAddresses[emailID]
	if !ok || email.UserID != userID {
		return credbound.ErrNotFound
	}
	if email.Primary {
		return credbound.ErrConflict
	}
	if email.VerifiedAt != nil {
		verified := 0
		for _, candidate := range s.emailAddresses {
			if candidate.UserID == userID && candidate.VerifiedAt != nil {
				verified++
			}
		}
		if verified <= 1 {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.emails, email.Address)
	delete(s.emailIDs, email.Address)
	delete(s.emailAddresses, emailID)
	delete(s.emailVerifications, emailID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// Emails streams the user's email addresses, newest first, as one cursor
// page.
func (s *Store) Emails(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.EmailAddress], error] {
	return func(yield func(credbound.PageEvent[credbound.EmailAddress], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.EmailAddress]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.EmailAddress, 0)
		for _, email := range s.emailAddresses {
			if email.UserID == userID && afterCursor(email.CreatedAt, email.ID, cursor) {
				values = append(values, cloneEmail(email))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for _, email := range values {
			if !yield(credbound.ItemEvent(email), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].CreatedAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.EmailAddress](end), nil)
	}
}

// TOTPByUserID returns the user's TOTP factor.
func (s *Store) TOTPByUserID(ctx context.Context, userID string) (credbound.TOTPFactor, error) {
	if err := ctx.Err(); err != nil {
		return credbound.TOTPFactor{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	factor, ok := s.totp[userID]
	if !ok {
		return credbound.TOTPFactor{}, credbound.ErrNotFound
	}
	return cloneTOTP(factor), nil
}

// SaveTOTPEnrollment stores a pending TOTP factor, replacing any prior
// pending enrollment; an already-active factor reports
// credbound.ErrConflict.
func (s *Store) SaveTOTPEnrollment(ctx context.Context, factor credbound.TOTPFactor, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.totp[factor.UserID]; ok && existing.Active {
		return credbound.ErrConflict
	}
	if _, ok := s.users[factor.UserID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.totp[factor.UserID] = cloneTOTP(factor)
	delete(s.recovery, factor.UserID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// ActivateTOTP activates the pending factor and stores its recovery codes in
// the same commit.
func (s *Store) ActivateTOTP(ctx context.Context, factor credbound.TOTPFactor, recovery []credbound.RecoveryCode, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.totp[factor.UserID]
	if !ok || existing.Active {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.totp[factor.UserID] = cloneTOTP(factor)
	s.recovery[factor.UserID] = cloneRecovery(recovery)
	return s.finishCommitLocked(ctx, commit, previous)
}

// UseTOTP records a successful code for the given time step, reporting false
// without error when the step was already consumed (replay).
func (s *Store) UseTOTP(ctx context.Context, userID string, step int64, commit credbound.Commit) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	factor, ok := s.totp[userID]
	if !ok || !factor.Active {
		return false, credbound.ErrNotFound
	}
	if step <= factor.LastUsedStep {
		return false, nil
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return false, err
	}
	factor.LastUsedStep = step
	factor.UpdatedAt = commit.Audit.OccurredAt
	s.totp[userID] = factor
	s.touchLastSeenLocked(userID, commit.Audit.OccurredAt)
	delete(s.throttles, userID)
	if err := s.finishCommitLocked(ctx, commit, previous); err != nil {
		return false, err
	}
	return true, nil
}

// ConsumeRecoveryCode marks the matching unused recovery code used,
// reporting false when no unused code matches the digest.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID string, digest []byte, usedAt time.Time, commit credbound.Commit) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	codes := s.recovery[userID]
	for index := range codes {
		if codes[index].UsedAt == nil && hmac.Equal(codes[index].Digest, digest) {
			previous, err := s.prepareCommitLocked(commit)
			if err != nil {
				return false, err
			}
			codes[index].UsedAt = cloneTime(&usedAt)
			s.recovery[userID] = codes
			s.touchLastSeenLocked(userID, usedAt)
			delete(s.throttles, userID)
			if err := s.finishCommitLocked(ctx, commit, previous); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// CountUnusedRecoveryCodes reports how many of the user's recovery codes
// remain unused.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := int64(0)
	for _, code := range s.recovery[userID] {
		if code.UsedAt == nil {
			count++
		}
	}
	return count, nil
}

// DisableTOTP removes the user's TOTP factor and recovery codes.
func (s *Store) DisableTOTP(ctx context.Context, userID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.totp[userID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.totp, userID)
	delete(s.recovery, userID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// Passkeys streams the user's passkeys in creation order.
func (s *Store) Passkeys(ctx context.Context, userID string) iter.Seq2[credbound.Passkey, error] {
	return func(yield func(credbound.Passkey, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(credbound.Passkey{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.Passkey, 0, len(s.passkeys[userID]))
		for _, passkey := range s.passkeys[userID] {
			values = append(values, clonePasskey(passkey))
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			if values[i].CreatedAt.Equal(values[j].CreatedAt) {
				return values[i].ID < values[j].ID
			}
			return values[i].CreatedAt.Before(values[j].CreatedAt)
		})
		for _, passkey := range values {
			if err := ctx.Err(); err != nil {
				yield(credbound.Passkey{}, err)
				return
			}
			if !yield(passkey, nil) {
				return
			}
		}
	}
}

// SavePasskey stores a new passkey; a credential ID already registered to
// any user reports credbound.ErrConflict.
func (s *Store) SavePasskey(ctx context.Context, passkey credbound.Passkey, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[passkey.UserID]; !ok {
		return credbound.ErrNotFound
	}
	for _, byID := range s.passkeys {
		for _, existing := range byID {
			if hmac.Equal(existing.CredentialID, passkey.CredentialID) {
				return credbound.ErrConflict
			}
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if s.passkeys[passkey.UserID] == nil {
		s.passkeys[passkey.UserID] = make(map[string]credbound.Passkey)
	}
	s.passkeys[passkey.UserID][passkey.ID] = clonePasskey(passkey)
	return s.finishCommitLocked(ctx, commit, previous)
}

// TouchPasskey persists the credential's updated JSON (sign counter) and
// last-used time after a successful assertion.
func (s *Store) TouchPasskey(ctx context.Context, userID string, credentialID, credentialJSON []byte, usedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, passkey := range s.passkeys[userID] {
		if hmac.Equal(passkey.CredentialID, credentialID) {
			previous, err := s.prepareCommitLocked(commit)
			if err != nil {
				return err
			}
			passkey.CredentialJSON = slices.Clone(credentialJSON)
			passkey.LastUsedAt = cloneTime(&usedAt)
			s.passkeys[userID][id] = passkey
			s.touchLastSeenLocked(userID, usedAt)
			return s.finishCommitLocked(ctx, commit, previous)
		}
	}
	return credbound.ErrNotFound
}

// DeletePasskey removes one of the user's passkeys.
func (s *Store) DeletePasskey(ctx context.Context, userID, passkeyID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.passkeys[userID][passkeyID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.passkeys[userID], passkeyID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreatePAT stores a personal access token record; a duplicate ID or prefix
// reports credbound.ErrConflict.
func (s *Store) CreatePAT(ctx context.Context, pat credbound.PAT, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pats[pat.ID]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.patPrefixes[pat.Prefix]; ok {
		return credbound.ErrConflict
	}
	if _, ok := s.users[pat.UserID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.pats[pat.ID] = clonePAT(pat)
	s.patPrefixes[pat.Prefix] = pat.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// PATByPrefix returns the token record addressed by its lookup prefix.
func (s *Store) PATByPrefix(ctx context.Context, prefix string) (credbound.PAT, error) {
	if err := ctx.Err(); err != nil {
		return credbound.PAT{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.patPrefixes[prefix]
	if !ok {
		return credbound.PAT{}, credbound.ErrNotFound
	}
	return clonePAT(s.pats[id]), nil
}

// TouchPAT records a token use, updating the token's and user's last-seen
// times.
func (s *Store) TouchPAT(ctx context.Context, id string, usedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pat, ok := s.pats[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	pat.LastUsedAt = cloneTime(&usedAt)
	s.pats[id] = pat
	s.touchLastSeenLocked(pat.UserID, usedAt)
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokePAT marks the user's token revoked.
func (s *Store) RevokePAT(ctx context.Context, userID, id string, revokedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pat, ok := s.pats[id]
	if !ok || pat.UserID != userID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	pat.RevokedAt = cloneTime(&revokedAt)
	s.pats[id] = pat
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeUserCredentials revokes all of the user's tokens (PATs and OAuth)
// and sessions in one commit.
func (s *Store) RevokeUserCredentials(ctx context.Context, userID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.revokeUserCredentialsLocked(userID, "", at)
	s.revokeUserSessionsLocked(userID, at)
	return s.finishCommitLocked(ctx, commit, previous)
}

// PATs streams the user's tokens, newest first, as one cursor page with
// digests omitted.
func (s *Store) PATs(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.PAT], error] {
	return func(yield func(credbound.PageEvent[credbound.PAT], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.PAT]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.PAT]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.PAT, 0)
		for _, pat := range s.pats {
			if pat.UserID == userID && afterCursor(pat.CreatedAt, pat.ID, cursor) {
				values = append(values, clonePAT(pat))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for index := range values {
			if err := ctx.Err(); err != nil {
				yield(credbound.PageEvent[credbound.PAT]{}, err)
				return
			}
			values[index].Digest = nil
			if !yield(credbound.ItemEvent(values[index]), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].CreatedAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.PAT](end), nil)
	}
}

// CreateSession stores a server-side session; a duplicate ID reports
// credbound.ErrConflict.
func (s *Store) CreateSession(ctx context.Context, session credbound.Session, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session.ID]; exists {
		return credbound.ErrConflict
	}
	if _, ok := s.users[session.UserID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.sessions[session.ID] = cloneSession(session)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SessionByID returns the session with the given ID.
func (s *Store) SessionByID(ctx context.Context, id string) (credbound.Session, error) {
	if err := ctx.Err(); err != nil {
		return credbound.Session{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return credbound.Session{}, credbound.ErrNotFound
	}
	return cloneSession(session), nil
}

// TouchSession updates the session's and user's last-seen times.
func (s *Store) TouchSession(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	session.LastSeenAt = at
	s.sessions[id] = session
	s.touchLastSeenLocked(session.UserID, at)
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeSession marks the session revoked; an already-revoked session is
// left unchanged.
func (s *Store) RevokeSession(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if session.RevokedAt == nil {
		session.RevokedAt = cloneTime(&at)
		s.sessions[id] = session
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeUserSessions revokes every session of the user.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.revokeUserSessionsLocked(userID, at)
	return s.finishCommitLocked(ctx, commit, previous)
}

// Sessions streams the user's sessions, newest first, as one cursor page
// with digests omitted.
func (s *Store) Sessions(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Session], error] {
	return func(yield func(credbound.PageEvent[credbound.Session], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Session]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Session]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.Session, 0)
		for _, session := range s.sessions {
			if session.UserID == userID && afterCursor(session.CreatedAt, session.ID, cursor) {
				values = append(values, cloneSession(session))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for index := range values {
			if err := ctx.Err(); err != nil {
				yield(credbound.PageEvent[credbound.Session]{}, err)
				return
			}
			values[index].Digest = nil
			if !yield(credbound.ItemEvent(values[index]), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].CreatedAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.Session](end), nil)
	}
}

// CreateWorkspaceDomain stores an unconfirmed domain claim; a domain already
// claimed by any workspace reports credbound.ErrConflict.
func (s *Store) CreateWorkspaceDomain(ctx context.Context, domain credbound.WorkspaceDomain, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workspaces[domain.WorkspaceID]; !exists {
		return credbound.ErrNotFound
	}
	if _, exists := s.domains[domain.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.domainNames[domain.Domain]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.domains[domain.ID] = cloneWorkspaceDomain(domain)
	s.domainNames[domain.Domain] = domain.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// WorkspaceDomainByID returns the domain record with the given ID.
func (s *Store) WorkspaceDomainByID(ctx context.Context, id string) (credbound.WorkspaceDomain, error) {
	if err := ctx.Err(); err != nil {
		return credbound.WorkspaceDomain{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	domain, ok := s.domains[id]
	if !ok {
		return credbound.WorkspaceDomain{}, credbound.ErrNotFound
	}
	return cloneWorkspaceDomain(domain), nil
}

// ConfirmedWorkspaceDomainByName resolves a confirmed domain by name;
// unknown or unconfirmed domains report credbound.ErrNotFound.
func (s *Store) ConfirmedWorkspaceDomainByName(ctx context.Context, name string) (credbound.WorkspaceDomain, error) {
	if err := ctx.Err(); err != nil {
		return credbound.WorkspaceDomain{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.domainNames[name]
	if !ok {
		return credbound.WorkspaceDomain{}, credbound.ErrNotFound
	}
	domain := s.domains[id]
	if domain.ConfirmedAt == nil {
		return credbound.WorkspaceDomain{}, credbound.ErrNotFound
	}
	return cloneWorkspaceDomain(domain), nil
}

// ConfirmWorkspaceDomain marks the domain verified; confirming twice reports
// credbound.ErrConflict.
func (s *Store) ConfirmWorkspaceDomain(ctx context.Context, id string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[id]
	if !ok {
		return credbound.ErrNotFound
	}
	if domain.ConfirmedAt != nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	domain.ConfirmedAt = cloneTime(&at)
	domain.UpdatedAt = at
	s.domains[id] = domain
	return s.finishCommitLocked(ctx, commit, previous)
}

// UpdateWorkspaceDomainPolicy replaces the auto-join and SSO-enforcement
// policy of a confirmed domain; an unconfirmed domain reports
// credbound.ErrConflict.
func (s *Store) UpdateWorkspaceDomainPolicy(ctx context.Context, id string, policy credbound.WorkspaceDomainPolicyInput, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[id]
	if !ok {
		return credbound.ErrNotFound
	}
	if domain.ConfirmedAt == nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	domain.AutoJoin, domain.AutoJoinRole = policy.AutoJoin, policy.AutoJoinRole
	domain.SSOProviderConfigurationID, domain.EnforceSSO = policy.SSOProviderConfigurationID, policy.EnforceSSO
	domain.UpdatedAt = at
	s.domains[id] = domain
	return s.finishCommitLocked(ctx, commit, previous)
}

// DeleteWorkspaceDomain removes the domain claim.
func (s *Store) DeleteWorkspaceDomain(ctx context.Context, id string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	domain, ok := s.domains[id]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.domainNames, domain.Domain)
	delete(s.domains, id)
	return s.finishCommitLocked(ctx, commit, previous)
}

// WorkspaceDomains streams the workspace's domains, newest first, as one
// cursor page.
func (s *Store) WorkspaceDomains(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.WorkspaceDomain], error] {
	return func(yield func(credbound.PageEvent[credbound.WorkspaceDomain], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.WorkspaceDomain, 0)
		for _, domain := range s.domains {
			if domain.WorkspaceID == workspaceID && afterCursor(domain.CreatedAt, domain.ID, cursor) {
				values = append(values, cloneWorkspaceDomain(domain))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for _, domain := range values {
			if err := ctx.Err(); err != nil {
				yield(credbound.PageEvent[credbound.WorkspaceDomain]{}, err)
				return
			}
			if !yield(credbound.ItemEvent(domain), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].CreatedAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.WorkspaceDomain](end), nil)
	}
}

// JITProvisionSSOUser atomically creates a user with a verified email,
// workspace membership and linked SSO identity for domain-based just-in-time
// provisioning.
func (s *Store) JITProvisionSSOUser(ctx context.Context, user credbound.User, email credbound.EmailAddress, membership credbound.Membership, identity credbound.SSOIdentity, _ time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[user.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.workspaces[membership.WorkspaceID]; !exists {
		return credbound.ErrNotFound
	}
	key := ssoKey(identity.ProviderConfigurationID, identity.Issuer, identity.Subject)
	if _, exists := s.ssoIdentities[identity.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.ssoKeys[key]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.users[user.ID] = cloneUser(user)
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	s.emails[email.Address] = user.ID
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	s.memberships[membership.WorkspaceID][user.ID] = normalizeMembership(membership)
	s.ssoIdentities[identity.ID] = cloneSSOIdentity(identity)
	s.ssoKeys[key] = identity.ID
	return s.finishCommitLocked(ctx, commit, previous)
}

// CreateWorkspace inserts a workspace together with its owning membership.
func (s *Store) CreateWorkspace(ctx context.Context, workspace credbound.Workspace, owner credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workspaces[workspace.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.users[owner.UserID]; !exists {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.workspaces[workspace.ID] = cloneWorkspace(workspace)
	s.memberships[workspace.ID] = map[string]credbound.Membership{owner.UserID: normalizeMembership(owner)}
	return s.finishCommitLocked(ctx, commit, previous)
}

// WorkspaceByID returns the workspace with the given ID.
func (s *Store) WorkspaceByID(ctx context.Context, workspaceID string) (credbound.Workspace, error) {
	if err := ctx.Err(); err != nil {
		return credbound.Workspace{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	workspace, ok := s.workspaces[workspaceID]
	if !ok {
		return credbound.Workspace{}, credbound.ErrNotFound
	}
	return cloneWorkspace(workspace), nil
}

// UpdateWorkspace persists the workspace's mutable attributes.
func (s *Store) UpdateWorkspace(ctx context.Context, workspace credbound.Workspace, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.workspaces[workspace.ID]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	workspace.CreatedAt = current.CreatedAt
	s.workspaces[workspace.ID] = cloneWorkspace(workspace)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SetWorkspaceDisabled enables or disables the workspace; disabling revokes
// the members' workspace-scoped tokens.
func (s *Store) SetWorkspaceDisabled(ctx context.Context, workspaceID string, disabled bool, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	workspace, ok := s.workspaces[workspaceID]
	if !ok {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	workspace.DisabledAt = nil
	if disabled {
		workspace.DisabledAt = cloneTime(&at)
	}
	workspace.UpdatedAt = at
	s.workspaces[workspaceID] = cloneWorkspace(workspace)
	if disabled {
		for userID := range s.memberships[workspaceID] {
			s.revokeUserCredentialsLocked(userID, workspaceID, at)
		}
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// Workspaces streams all workspaces, newest first, as one cursor page.
func (s *Store) Workspaces(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return s.workspacesPage(ctx, "", page)
}

// UserWorkspaces streams the workspaces the user belongs to, newest first,
// as one cursor page.
func (s *Store) UserWorkspaces(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return s.workspacesPage(ctx, userID, page)
}

func (s *Store) workspacesPage(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Workspace], error] {
	return func(yield func(credbound.PageEvent[credbound.Workspace], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Workspace]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Workspace]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.Workspace, 0)
		for id, workspace := range s.workspaces {
			if userID != "" {
				if _, member := s.memberships[id][userID]; !member {
					continue
				}
			}
			if afterCursor(workspace.CreatedAt, workspace.ID, cursor) {
				values = append(values, cloneWorkspace(workspace))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.Workspace) (time.Time, string) { return value.CreatedAt, value.ID }, yield)
	}
}

// Membership returns the user's membership in the workspace.
func (s *Store) Membership(ctx context.Context, workspaceID, userID string) (credbound.Membership, error) {
	if err := ctx.Err(); err != nil {
		return credbound.Membership{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	membership, ok := s.memberships[workspaceID][userID]
	if !ok {
		return credbound.Membership{}, credbound.ErrNotFound
	}
	return normalizeMembership(membership), nil
}

func cloneInvitation(value credbound.WorkspaceInvitation) credbound.WorkspaceInvitation {
	value.Digest = slices.Clone(value.Digest)
	value.AcceptedAt = cloneTime(value.AcceptedAt)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

// CreateWorkspaceInvitation stores an invitation; a pending invitation for
// the same address in the workspace reports credbound.ErrConflict.
func (s *Store) CreateWorkspaceInvitation(ctx context.Context, invitation credbound.WorkspaceInvitation, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.workspaces[invitation.WorkspaceID]; !exists {
		return credbound.ErrNotFound
	}
	if _, exists := s.invitations[invitation.ID]; exists {
		return credbound.ErrConflict
	}
	for _, other := range s.invitations {
		if other.WorkspaceID == invitation.WorkspaceID && other.Email == invitation.Email && other.AcceptedAt == nil && other.RevokedAt == nil {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.invitations[invitation.ID] = cloneInvitation(invitation)
	return s.finishCommitLocked(ctx, commit, previous)
}

// WorkspaceInvitationByID returns the invitation with the given ID.
func (s *Store) WorkspaceInvitationByID(ctx context.Context, invitationID string) (credbound.WorkspaceInvitation, error) {
	if err := ctx.Err(); err != nil {
		return credbound.WorkspaceInvitation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	invitation, ok := s.invitations[invitationID]
	if !ok {
		return credbound.WorkspaceInvitation{}, credbound.ErrNotFound
	}
	return cloneInvitation(invitation), nil
}

// PendingWorkspaceInvitation returns the workspace's unaccepted, unrevoked
// invitation for the email address.
func (s *Store) PendingWorkspaceInvitation(ctx context.Context, workspaceID, email string) (credbound.WorkspaceInvitation, error) {
	if err := ctx.Err(); err != nil {
		return credbound.WorkspaceInvitation{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, invitation := range s.invitations {
		if invitation.WorkspaceID == workspaceID && invitation.Email == email && invitation.AcceptedAt == nil && invitation.RevokedAt == nil {
			return cloneInvitation(invitation), nil
		}
	}
	return credbound.WorkspaceInvitation{}, credbound.ErrNotFound
}

// AcceptWorkspaceInvitation marks the invitation accepted by the user and
// installs the resulting membership in the same commit; an accepted or
// revoked invitation reports credbound.ErrConflict.
func (s *Store) AcceptWorkspaceInvitation(ctx context.Context, invitationID, userID string, at time.Time, membership credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.invitations[invitationID]
	if !ok {
		return credbound.ErrNotFound
	}
	if invitation.AcceptedAt != nil || invitation.RevokedAt != nil {
		return credbound.ErrConflict
	}
	if _, exists := s.users[userID]; !exists {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	invitation.AcceptedAt = cloneTime(&at)
	invitation.AcceptedUserID = userID
	s.invitations[invitationID] = invitation
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	s.memberships[membership.WorkspaceID][userID] = normalizeMembership(membership)
	return s.finishCommitLocked(ctx, commit, previous)
}

// RegisterInvitedUser atomically creates the invited user with email,
// password and membership while accepting the invitation.
func (s *Store) RegisterInvitedUser(ctx context.Context, invitationID string, user credbound.User, email credbound.EmailAddress, password credbound.PasswordCredential, membership credbound.Membership, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.invitations[invitationID]
	if !ok {
		return credbound.ErrNotFound
	}
	if invitation.AcceptedAt != nil || invitation.RevokedAt != nil {
		return credbound.ErrConflict
	}
	if _, exists := s.users[user.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.emailIDs[email.Address]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.workspaces[membership.WorkspaceID]; !exists {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	invitation.AcceptedAt = cloneTime(&at)
	invitation.AcceptedUserID = user.ID
	s.invitations[invitationID] = invitation
	s.users[user.ID] = cloneUser(user)
	s.emails[email.Address] = user.ID
	s.emailAddresses[email.ID] = cloneEmail(email)
	s.emailIDs[email.Address] = email.ID
	s.passwords[user.ID] = password
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	s.memberships[membership.WorkspaceID][user.ID] = normalizeMembership(membership)
	return s.finishCommitLocked(ctx, commit, previous)
}

// RevokeWorkspaceInvitation marks the workspace's invitation revoked; an
// accepted or already-revoked invitation reports credbound.ErrConflict.
func (s *Store) RevokeWorkspaceInvitation(ctx context.Context, workspaceID, invitationID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invitation, ok := s.invitations[invitationID]
	if !ok || invitation.WorkspaceID != workspaceID {
		return credbound.ErrNotFound
	}
	if invitation.AcceptedAt != nil || invitation.RevokedAt != nil {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	invitation.RevokedAt = cloneTime(&at)
	s.invitations[invitationID] = invitation
	return s.finishCommitLocked(ctx, commit, previous)
}

// WorkspaceInvitations streams the workspace's invitations, newest first, as
// one cursor page.
func (s *Store) WorkspaceInvitations(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.WorkspaceInvitation], error] {
	return func(yield func(credbound.PageEvent[credbound.WorkspaceInvitation], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.WorkspaceInvitation]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.WorkspaceInvitation, 0)
		for _, invitation := range s.invitations {
			if invitation.WorkspaceID == workspaceID && afterCursor(invitation.CreatedAt, invitation.ID, cursor) {
				values = append(values, cloneInvitation(invitation))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for _, value := range values {
			if !yield(credbound.ItemEvent(value), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore {
			last := values[len(values)-1]
			end.NextCursor = encodeCursor(last.CreatedAt, last.ID)
		}
		yield(credbound.EndEvent[credbound.WorkspaceInvitation](end), nil)
	}
}

// UpsertMembership inserts or updates a membership, refusing a change that
// would leave the workspace without an active admin (credbound.ErrConflict);
// deactivation revokes the member's workspace-scoped tokens.
func (s *Store) UpsertMembership(ctx context.Context, membership credbound.Membership, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.workspaces[membership.WorkspaceID]; !ok {
		return credbound.ErrNotFound
	}
	if _, ok := s.users[membership.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if existing, ok := s.memberships[membership.WorkspaceID][membership.UserID]; ok &&
		existing.Role == credbound.RoleAdmin && existing.Status == credbound.MembershipActive &&
		(membership.Role != credbound.RoleAdmin || membership.Status != credbound.MembershipActive) &&
		s.activeWorkspaceAdminsLocked(membership.WorkspaceID) <= 1 {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if s.memberships[membership.WorkspaceID] == nil {
		s.memberships[membership.WorkspaceID] = make(map[string]credbound.Membership)
	}
	if existing, ok := s.memberships[membership.WorkspaceID][membership.UserID]; ok {
		membership.CreatedAt = existing.CreatedAt
	}
	s.memberships[membership.WorkspaceID][membership.UserID] = normalizeMembership(membership)
	if membership.Status != credbound.MembershipActive {
		s.revokeUserCredentialsLocked(membership.UserID, membership.WorkspaceID, commit.Audit.OccurredAt)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// RemoveMembership deletes the membership, refusing to remove the
// workspace's last active admin (credbound.ErrConflict) and revoking the
// member's workspace-scoped tokens.
func (s *Store) RemoveMembership(ctx context.Context, workspaceID, userID string, at time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	membership, ok := s.memberships[workspaceID][userID]
	if !ok {
		return credbound.ErrNotFound
	}
	if membership.Role == credbound.RoleAdmin && membership.Status == credbound.MembershipActive && s.activeWorkspaceAdminsLocked(workspaceID) <= 1 {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.memberships[workspaceID], userID)
	s.revokeUserCredentialsLocked(userID, workspaceID, at)
	return s.finishCommitLocked(ctx, commit, previous)
}

// Memberships streams the workspace's memberships, newest first, as one
// cursor page.
func (s *Store) Memberships(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.Membership], error] {
	return func(yield func(credbound.PageEvent[credbound.Membership], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.Membership]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.Membership]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.Membership, 0, len(s.memberships[workspaceID]))
		for _, membership := range s.memberships[workspaceID] {
			if afterCursor(membership.CreatedAt, membership.UserID, cursor) {
				values = append(values, normalizeMembership(membership))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].UserID, values[j].CreatedAt, values[j].UserID)
		})
		yieldMemoryPage(values, page.Limit, func(value credbound.Membership) (time.Time, string) { return value.CreatedAt, value.UserID }, yield)
	}
}

// InstanceAdministrator returns the user's instance-administration role.
func (s *Store) InstanceAdministrator(ctx context.Context, userID string) (credbound.InstanceAdministrator, error) {
	if err := ctx.Err(); err != nil {
		return credbound.InstanceAdministrator{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	admin, ok := s.admins[userID]
	if !ok {
		return credbound.InstanceAdministrator{}, credbound.ErrNotFound
	}
	return admin, nil
}

// SetInstanceRole grants or changes a user's instance role, refusing to
// demote the last root administrator (credbound.ErrConflict).
func (s *Store) SetInstanceRole(ctx context.Context, admin credbound.InstanceAdministrator, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[admin.UserID]; !ok {
		return credbound.ErrNotFound
	}
	if existing, ok := s.admins[admin.UserID]; ok && existing.Role == credbound.InstanceRoleRoot && admin.Role != credbound.InstanceRoleRoot {
		roots := 0
		for _, candidate := range s.admins {
			if candidate.Role == credbound.InstanceRoleRoot {
				roots++
			}
		}
		if roots <= 1 {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	if existing, ok := s.admins[admin.UserID]; ok {
		admin.CreatedAt = existing.CreatedAt
	}
	s.admins[admin.UserID] = admin
	return s.finishCommitLocked(ctx, commit, previous)
}

// RemoveInstanceRole revokes the user's instance role, refusing to remove
// the last root administrator (credbound.ErrConflict).
func (s *Store) RemoveInstanceRole(ctx context.Context, userID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	admin, ok := s.admins[userID]
	if !ok {
		return credbound.ErrNotFound
	}
	if admin.Role == credbound.InstanceRoleRoot {
		roots := 0
		for _, candidate := range s.admins {
			if candidate.Role == credbound.InstanceRoleRoot {
				roots++
			}
		}
		if roots <= 1 {
			return credbound.ErrConflict
		}
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.admins, userID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SSOIdentity resolves a linked identity by provider configuration, issuer
// and subject.
func (s *Store) SSOIdentity(ctx context.Context, providerConfigurationID, issuer, subject string) (credbound.SSOIdentity, error) {
	if err := ctx.Err(); err != nil {
		return credbound.SSOIdentity{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.ssoKeys[ssoKey(providerConfigurationID, issuer, subject)]
	if !ok {
		return credbound.SSOIdentity{}, credbound.ErrNotFound
	}
	return cloneSSOIdentity(s.ssoIdentities[id]), nil
}

// LinkSSO stores a new SSO identity link; an identity already linked to any
// user reports credbound.ErrConflict.
func (s *Store) LinkSSO(ctx context.Context, identity credbound.SSOIdentity, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[identity.UserID]; !ok {
		return credbound.ErrNotFound
	}
	key := ssoKey(identity.ProviderConfigurationID, identity.Issuer, identity.Subject)
	if _, exists := s.ssoIdentities[identity.ID]; exists {
		return credbound.ErrConflict
	}
	if _, exists := s.ssoKeys[key]; exists {
		return credbound.ErrConflict
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	s.ssoIdentities[identity.ID] = cloneSSOIdentity(identity)
	s.ssoKeys[key] = identity.ID
	if identity.LastUsedAt != nil {
		s.touchLastSeenLocked(identity.UserID, *identity.LastUsedAt)
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// TouchSSO updates the identity's last-used time and the user's last-seen
// time after a successful SSO login.
func (s *Store) TouchSSO(ctx context.Context, userID, identityID string, usedAt time.Time, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.ssoIdentities[identityID]
	if !ok || identity.UserID != userID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	identity.LastUsedAt = cloneTime(&usedAt)
	s.ssoIdentities[identityID] = identity
	s.touchLastSeenLocked(userID, usedAt)
	return s.finishCommitLocked(ctx, commit, previous)
}

// UnlinkSSO removes the user's SSO identity link.
func (s *Store) UnlinkSSO(ctx context.Context, userID, identityID string, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.ssoIdentities[identityID]
	if !ok || identity.UserID != userID {
		return credbound.ErrNotFound
	}
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	delete(s.ssoKeys, ssoKey(identity.ProviderConfigurationID, identity.Issuer, identity.Subject))
	delete(s.ssoIdentities, identityID)
	return s.finishCommitLocked(ctx, commit, previous)
}

// SSOIdentities streams the user's SSO identity links, newest first, as one
// cursor page.
func (s *Store) SSOIdentities(ctx context.Context, userID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.SSOIdentity], error] {
	return func(yield func(credbound.PageEvent[credbound.SSOIdentity], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.SSOIdentity, 0)
		for _, identity := range s.ssoIdentities {
			if identity.UserID == userID && afterCursor(identity.CreatedAt, identity.ID, cursor) {
				values = append(values, cloneSSOIdentity(identity))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].CreatedAt, values[i].ID, values[j].CreatedAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for _, identity := range values {
			if err := ctx.Err(); err != nil {
				yield(credbound.PageEvent[credbound.SSOIdentity]{}, err)
				return
			}
			if !yield(credbound.ItemEvent(identity), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].CreatedAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.SSOIdentity](end), nil)
	}
}

// AppendAudit commits a standalone audit event (and any transactional hook)
// without another mutation.
func (s *Store) AppendAudit(ctx context.Context, commit credbound.Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, err := s.prepareCommitLocked(commit)
	if err != nil {
		return err
	}
	return s.finishCommitLocked(ctx, commit, previous)
}

// AuditEvents streams the workspace's audit events, newest first, as one
// cursor page.
func (s *Store) AuditEvents(ctx context.Context, workspaceID string, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return s.auditEvents(ctx, page, func(event credbound.AuditEvent) bool { return event.WorkspaceID == workspaceID })
}

// InstanceAuditEvents streams audit events across the whole instance, newest
// first, as one cursor page.
func (s *Store) InstanceAuditEvents(ctx context.Context, page credbound.PageRequest) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return s.auditEvents(ctx, page, func(credbound.AuditEvent) bool { return true })
}

func (s *Store) auditEvents(ctx context.Context, page credbound.PageRequest, include func(credbound.AuditEvent) bool) iter.Seq2[credbound.PageEvent[credbound.AuditEvent], error] {
	return func(yield func(credbound.PageEvent[credbound.AuditEvent], error) bool) {
		cursor, err := decodeCursor(page.Cursor)
		if err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		if err := ctx.Err(); err != nil {
			yield(credbound.PageEvent[credbound.AuditEvent]{}, err)
			return
		}
		s.mu.RLock()
		values := make([]credbound.AuditEvent, 0)
		for _, event := range s.audits {
			if include(event) && afterCursor(event.OccurredAt, event.ID, cursor) {
				values = append(values, cloneAuditEvent(event))
			}
		}
		s.mu.RUnlock()
		sort.Slice(values, func(i, j int) bool {
			return newer(values[i].OccurredAt, values[i].ID, values[j].OccurredAt, values[j].ID)
		})
		hasMore := len(values) > page.Limit
		if hasMore {
			values = values[:page.Limit]
		}
		for _, event := range values {
			if !yield(credbound.ItemEvent(event), nil) {
				return
			}
		}
		end := credbound.PageEnd{HasMore: hasMore}
		if hasMore && len(values) > 0 {
			end.NextCursor = encodeCursor(values[len(values)-1].OccurredAt, values[len(values)-1].ID)
		}
		yield(credbound.EndEvent[credbound.AuditEvent](end), nil)
	}
}

type storeState struct {
	users              map[string]credbound.User
	emails             map[string]string
	emailAddresses     map[string]credbound.EmailAddress
	emailIDs           map[string]string
	emailVerifications map[string]credbound.EmailVerificationCredential
	passwords          map[string]credbound.PasswordCredential
	workspaces         map[string]credbound.Workspace
	memberships        map[string]map[string]credbound.Membership
	admins             map[string]credbound.InstanceAdministrator
	ssoIdentities      map[string]credbound.SSOIdentity
	ssoKeys            map[string]string
	totp               map[string]credbound.TOTPFactor
	recovery           map[string][]credbound.RecoveryCode
	passkeys           map[string]map[string]credbound.Passkey
	pats               map[string]credbound.PAT
	patPrefixes        map[string]string
	sessions           map[string]credbound.Session
	domains            map[string]credbound.WorkspaceDomain
	domainNames        map[string]string
	scimConfigurations map[string]credbound.SCIMConfiguration
	scimCredentials    map[string]credbound.SCIMCredential
	scimCredentialKeys map[string]string
	scimUsers          map[string]credbound.SCIMUser
	scimUserNames      map[string]string
	scimExternalIDs    map[string]string
	scimGroups         map[string]credbound.SCIMGroup
	scimGroupExternal  map[string]string
	oauthIssuers       map[string]credbound.OAuthIssuer
	oauthIssuerURLs    map[string]string
	oauthResources     map[string]credbound.OAuthProtectedResource
	oauthResourceURIs  map[string]string
	oauthClients       map[string]credbound.OAuthClient
	oauthClientKeys    map[string]string
	oauthInitialTokens map[string]credbound.OAuthInitialAccessToken
	oauthInitialKeys   map[string]string
	oauthGrants        map[string]credbound.OAuthGrant
	oauthCodes         map[string]credbound.OAuthAuthorizationCode
	oauthCodeKeys      map[string]string
	oauthAccessTokens  map[string]credbound.OAuthAccessToken
	oauthAccessKeys    map[string]string
	oauthRefreshTokens map[string]credbound.OAuthRefreshToken
	oauthRefreshKeys   map[string]string
	throttles          map[string]credbound.LoginThrottle
	passwordResets     map[string]credbound.PasswordResetCredential
	emailAuths         map[string]credbound.EmailAuthenticationCredential
	invitations        map[string]credbound.WorkspaceInvitation
	audits             []credbound.AuditEvent
	auditIDs           map[string]struct{}
	auditSequence      int64
	auditHead          []byte
}

func (s *Store) snapshotLocked() storeState {
	state := storeState{
		users: make(map[string]credbound.User, len(s.users)), emails: make(map[string]string, len(s.emails)),
		emailAddresses: make(map[string]credbound.EmailAddress, len(s.emailAddresses)), emailIDs: make(map[string]string, len(s.emailIDs)),
		emailVerifications: make(map[string]credbound.EmailVerificationCredential, len(s.emailVerifications)),
		passwords:          make(map[string]credbound.PasswordCredential, len(s.passwords)), workspaces: make(map[string]credbound.Workspace, len(s.workspaces)),
		memberships: make(map[string]map[string]credbound.Membership, len(s.memberships)), admins: make(map[string]credbound.InstanceAdministrator, len(s.admins)),
		ssoIdentities: make(map[string]credbound.SSOIdentity, len(s.ssoIdentities)), ssoKeys: make(map[string]string, len(s.ssoKeys)),
		totp: make(map[string]credbound.TOTPFactor, len(s.totp)), recovery: make(map[string][]credbound.RecoveryCode, len(s.recovery)),
		passkeys: make(map[string]map[string]credbound.Passkey, len(s.passkeys)), pats: make(map[string]credbound.PAT, len(s.pats)),
		patPrefixes: make(map[string]string, len(s.patPrefixes)), sessions: make(map[string]credbound.Session, len(s.sessions)),
		domains: make(map[string]credbound.WorkspaceDomain, len(s.domains)), domainNames: make(map[string]string, len(s.domainNames)),
		audits: slices.Clone(s.audits), auditIDs: make(map[string]struct{}, len(s.auditIDs)),
		auditSequence: s.auditSequence, auditHead: slices.Clone(s.auditHead),
		throttles:          make(map[string]credbound.LoginThrottle, len(s.throttles)),
		passwordResets:     make(map[string]credbound.PasswordResetCredential, len(s.passwordResets)),
		emailAuths:         make(map[string]credbound.EmailAuthenticationCredential, len(s.emailAuths)),
		invitations:        make(map[string]credbound.WorkspaceInvitation, len(s.invitations)),
		scimConfigurations: make(map[string]credbound.SCIMConfiguration, len(s.scimConfigurations)),
		scimCredentials:    make(map[string]credbound.SCIMCredential, len(s.scimCredentials)), scimCredentialKeys: make(map[string]string, len(s.scimCredentialKeys)),
		scimUsers: make(map[string]credbound.SCIMUser, len(s.scimUsers)), scimUserNames: make(map[string]string, len(s.scimUserNames)), scimExternalIDs: make(map[string]string, len(s.scimExternalIDs)),
		scimGroups: make(map[string]credbound.SCIMGroup, len(s.scimGroups)), scimGroupExternal: make(map[string]string, len(s.scimGroupExternal)),
		oauthIssuers: make(map[string]credbound.OAuthIssuer, len(s.oauthIssuers)), oauthIssuerURLs: make(map[string]string, len(s.oauthIssuerURLs)),
		oauthResources: make(map[string]credbound.OAuthProtectedResource, len(s.oauthResources)), oauthResourceURIs: make(map[string]string, len(s.oauthResourceURIs)),
		oauthClients: make(map[string]credbound.OAuthClient, len(s.oauthClients)), oauthClientKeys: make(map[string]string, len(s.oauthClientKeys)),
		oauthInitialTokens: make(map[string]credbound.OAuthInitialAccessToken, len(s.oauthInitialTokens)), oauthInitialKeys: make(map[string]string, len(s.oauthInitialKeys)),
		oauthGrants: make(map[string]credbound.OAuthGrant, len(s.oauthGrants)), oauthCodes: make(map[string]credbound.OAuthAuthorizationCode, len(s.oauthCodes)), oauthCodeKeys: make(map[string]string, len(s.oauthCodeKeys)),
		oauthAccessTokens: make(map[string]credbound.OAuthAccessToken, len(s.oauthAccessTokens)), oauthAccessKeys: make(map[string]string, len(s.oauthAccessKeys)),
		oauthRefreshTokens: make(map[string]credbound.OAuthRefreshToken, len(s.oauthRefreshTokens)), oauthRefreshKeys: make(map[string]string, len(s.oauthRefreshKeys)),
	}
	for key, value := range s.users {
		state.users[key] = cloneUser(value)
	}
	for key, value := range s.emails {
		state.emails[key] = value
	}
	for key, value := range s.emailAddresses {
		state.emailAddresses[key] = cloneEmail(value)
	}
	for key, value := range s.emailIDs {
		state.emailIDs[key] = value
	}
	for key, value := range s.emailVerifications {
		state.emailVerifications[key] = cloneEmailVerification(value)
	}
	for key, value := range s.passwords {
		state.passwords[key] = value
	}
	for key, value := range s.workspaces {
		state.workspaces[key] = cloneWorkspace(value)
	}
	for workspaceID, members := range s.memberships {
		state.memberships[workspaceID] = make(map[string]credbound.Membership, len(members))
		for userID, membership := range members {
			state.memberships[workspaceID][userID] = membership
		}
	}
	for key, value := range s.admins {
		state.admins[key] = value
	}
	for key, value := range s.ssoIdentities {
		state.ssoIdentities[key] = cloneSSOIdentity(value)
	}
	for key, value := range s.ssoKeys {
		state.ssoKeys[key] = value
	}
	for key, value := range s.totp {
		state.totp[key] = cloneTOTP(value)
	}
	for key, value := range s.recovery {
		state.recovery[key] = cloneRecovery(value)
	}
	for userID, passkeys := range s.passkeys {
		state.passkeys[userID] = make(map[string]credbound.Passkey, len(passkeys))
		for passkeyID, passkey := range passkeys {
			state.passkeys[userID][passkeyID] = clonePasskey(passkey)
		}
	}
	for key, value := range s.pats {
		state.pats[key] = clonePAT(value)
	}
	for key, value := range s.throttles {
		state.throttles[key] = cloneThrottle(value)
	}
	for key, value := range s.passwordResets {
		state.passwordResets[key] = clonePasswordReset(value)
	}
	for key, value := range s.emailAuths {
		state.emailAuths[key] = cloneEmailAuthentication(value)
	}
	for key, value := range s.invitations {
		state.invitations[key] = cloneInvitation(value)
	}
	for key, value := range s.patPrefixes {
		state.patPrefixes[key] = value
	}
	for key, value := range s.sessions {
		state.sessions[key] = cloneSession(value)
	}
	for key, value := range s.domains {
		state.domains[key] = cloneWorkspaceDomain(value)
	}
	for key, value := range s.domainNames {
		state.domainNames[key] = value
	}
	for key, value := range s.scimConfigurations {
		state.scimConfigurations[key] = cloneSCIMConfiguration(value)
	}
	for key, value := range s.scimCredentials {
		state.scimCredentials[key] = cloneSCIMCredential(value)
	}
	for key, value := range s.scimCredentialKeys {
		state.scimCredentialKeys[key] = value
	}
	for key, value := range s.scimUsers {
		state.scimUsers[key] = cloneSCIMUser(value)
	}
	for key, value := range s.scimUserNames {
		state.scimUserNames[key] = value
	}
	for key, value := range s.scimExternalIDs {
		state.scimExternalIDs[key] = value
	}
	for key, value := range s.scimGroups {
		state.scimGroups[key] = cloneSCIMGroup(value)
	}
	for key, value := range s.scimGroupExternal {
		state.scimGroupExternal[key] = value
	}
	for key, value := range s.oauthIssuers {
		state.oauthIssuers[key] = cloneOAuthIssuer(value)
	}
	for key, value := range s.oauthIssuerURLs {
		state.oauthIssuerURLs[key] = value
	}
	for key, value := range s.oauthResources {
		state.oauthResources[key] = cloneOAuthResource(value)
	}
	for key, value := range s.oauthResourceURIs {
		state.oauthResourceURIs[key] = value
	}
	for key, value := range s.oauthClients {
		state.oauthClients[key] = cloneOAuthClient(value)
	}
	for key, value := range s.oauthClientKeys {
		state.oauthClientKeys[key] = value
	}
	for key, value := range s.oauthInitialTokens {
		state.oauthInitialTokens[key] = cloneOAuthInitialToken(value)
	}
	for key, value := range s.oauthInitialKeys {
		state.oauthInitialKeys[key] = value
	}
	for key, value := range s.oauthGrants {
		state.oauthGrants[key] = cloneOAuthGrant(value)
	}
	for key, value := range s.oauthCodes {
		state.oauthCodes[key] = cloneOAuthCode(value)
	}
	for key, value := range s.oauthCodeKeys {
		state.oauthCodeKeys[key] = value
	}
	for key, value := range s.oauthAccessTokens {
		state.oauthAccessTokens[key] = cloneOAuthAccessToken(value)
	}
	for key, value := range s.oauthAccessKeys {
		state.oauthAccessKeys[key] = value
	}
	for key, value := range s.oauthRefreshTokens {
		state.oauthRefreshTokens[key] = cloneOAuthRefreshToken(value)
	}
	for key, value := range s.oauthRefreshKeys {
		state.oauthRefreshKeys[key] = value
	}
	for key := range s.auditIDs {
		state.auditIDs[key] = struct{}{}
	}
	return state
}

func (s *Store) restoreLocked(state storeState) {
	s.users, s.emails = state.users, state.emails
	s.emailAddresses, s.emailIDs, s.emailVerifications = state.emailAddresses, state.emailIDs, state.emailVerifications
	s.passwords, s.workspaces, s.memberships = state.passwords, state.workspaces, state.memberships
	s.admins, s.ssoIdentities, s.ssoKeys = state.admins, state.ssoIdentities, state.ssoKeys
	s.totp, s.recovery, s.passkeys = state.totp, state.recovery, state.passkeys
	s.pats, s.patPrefixes = state.pats, state.patPrefixes
	s.sessions = state.sessions
	s.domains, s.domainNames = state.domains, state.domainNames
	s.scimConfigurations, s.scimCredentials, s.scimCredentialKeys = state.scimConfigurations, state.scimCredentials, state.scimCredentialKeys
	s.scimUsers, s.scimUserNames, s.scimExternalIDs = state.scimUsers, state.scimUserNames, state.scimExternalIDs
	s.scimGroups, s.scimGroupExternal = state.scimGroups, state.scimGroupExternal
	s.oauthIssuers, s.oauthIssuerURLs = state.oauthIssuers, state.oauthIssuerURLs
	s.oauthResources, s.oauthResourceURIs = state.oauthResources, state.oauthResourceURIs
	s.oauthClients, s.oauthClientKeys = state.oauthClients, state.oauthClientKeys
	s.oauthInitialTokens, s.oauthInitialKeys = state.oauthInitialTokens, state.oauthInitialKeys
	s.oauthGrants, s.oauthCodes, s.oauthCodeKeys = state.oauthGrants, state.oauthCodes, state.oauthCodeKeys
	s.oauthAccessTokens, s.oauthAccessKeys = state.oauthAccessTokens, state.oauthAccessKeys
	s.oauthRefreshTokens, s.oauthRefreshKeys = state.oauthRefreshTokens, state.oauthRefreshKeys
	s.audits, s.auditIDs = state.audits, state.auditIDs
	s.auditSequence, s.auditHead = state.auditSequence, state.auditHead
	s.throttles = state.throttles
	s.passwordResets, s.emailAuths = state.passwordResets, state.emailAuths
	s.invitations = state.invitations
}

func (s *Store) prepareCommitLocked(commit credbound.Commit) (storeState, error) {
	if err := s.canAudit(commit.Audit); err != nil {
		return storeState{}, err
	}
	if commit.Transactional == nil {
		return storeState{}, nil
	}
	return s.snapshotLocked(), nil
}

func (s *Store) finishCommitLocked(ctx context.Context, commit credbound.Commit, previous storeState) error {
	if commit.Transactional != nil {
		tx := newTx(commit.Audit)
		err := commit.Transactional(ctx, tx)
		tx.close()
		if err != nil {
			s.restoreLocked(previous)
			return err
		}
	}
	s.commitAudit(commit.Audit)
	return nil
}

func (s *Store) canAudit(event credbound.AuditEvent) error {
	if s.auditFailure != nil {
		return fmt.Errorf("%w: %v", credbound.ErrAuditUnavailable, s.auditFailure)
	}
	if event.ID == "" || event.Action == "" || event.OccurredAt.IsZero() {
		return credbound.ErrAuditUnavailable
	}
	if _, duplicate := s.auditIDs[event.ID]; duplicate {
		return credbound.ErrConflict
	}
	return nil
}

func (s *Store) commitAudit(event credbound.AuditEvent) {
	if event.ActorKind == "" {
		event.ActorKind = credbound.ActorUser
	}
	event.Sequence = s.auditSequence + 1
	event.PreviousHash = slices.Clone(s.auditHead)
	event.Hash = credbound.ComputeAuditHash(event.PreviousHash, event)
	s.auditSequence = event.Sequence
	s.auditHead = slices.Clone(event.Hash)
	s.audits = append(s.audits, event)
	s.auditIDs[event.ID] = struct{}{}
}

// AuditChainHead returns the sequence number and hash of the latest chained
// audit event.
func (s *Store) AuditChainHead(ctx context.Context) (int64, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.auditSequence, slices.Clone(s.auditHead), nil
}

// ChainedAuditEvents streams every chained audit event in sequence order for
// verification with credbound.VerifyAuditChain.
func (s *Store) ChainedAuditEvents(ctx context.Context) iter.Seq2[credbound.AuditEvent, error] {
	return func(yield func(credbound.AuditEvent, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(credbound.AuditEvent{}, err)
			return
		}
		s.mu.RLock()
		chained := make([]credbound.AuditEvent, 0, len(s.audits))
		for _, event := range s.audits {
			if event.Sequence > 0 {
				chained = append(chained, cloneAuditEvent(event))
			}
		}
		s.mu.RUnlock()
		sort.Slice(chained, func(i, j int) bool { return chained[i].Sequence < chained[j].Sequence })
		for _, event := range chained {
			if !yield(event, nil) {
				return
			}
		}
	}
}

func cloneAuditEvent(event credbound.AuditEvent) credbound.AuditEvent {
	event.PreviousHash = slices.Clone(event.PreviousHash)
	event.Hash = slices.Clone(event.Hash)
	return event
}

func (s *Store) touchLastSeenLocked(userID string, seenAt time.Time) {
	user := s.users[userID]
	user.LastSeenAt = cloneTime(&seenAt)
	s.users[userID] = user
}

func ssoKey(providerConfigurationID, issuer, subject string) string {
	return providerConfigurationID + "\x00" + issuer + "\x00" + subject
}

type pageCursor struct {
	UnixNano int64  `json:"t"`
	ID       string `json:"id"`
}

func encodeCursor(timestamp time.Time, id string) string {
	payload, _ := json.Marshal(pageCursor{UnixNano: timestamp.UnixNano(), ID: id})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeCursor(raw string) (pageCursor, error) {
	if raw == "" {
		return pageCursor{}, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return pageCursor{}, credbound.ErrInvalidInput
	}
	var cursor pageCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.UnixNano == 0 || cursor.ID == "" {
		return pageCursor{}, credbound.ErrInvalidInput
	}
	return cursor, nil
}

func afterCursor(timestamp time.Time, id string, cursor pageCursor) bool {
	if cursor.ID == "" {
		return true
	}
	ct := time.Unix(0, cursor.UnixNano)
	return timestamp.Before(ct) || (timestamp.Equal(ct) && id < cursor.ID)
}

func newer(leftTime time.Time, leftID string, rightTime time.Time, rightID string) bool {
	if leftTime.Equal(rightTime) {
		return leftID > rightID
	}
	return leftTime.After(rightTime)
}

func cloneUser(value credbound.User) credbound.User {
	value.LastSeenAt = cloneTime(value.LastSeenAt)
	return value
}

func cloneWorkspace(value credbound.Workspace) credbound.Workspace {
	value.DisabledAt = cloneTime(value.DisabledAt)
	return value
}

func (s *Store) activeWorkspaceAdminsLocked(workspaceID string) int {
	count := 0
	for _, membership := range s.memberships[workspaceID] {
		if membership.Role == credbound.RoleAdmin && membership.Status == credbound.MembershipActive {
			count++
		}
	}
	return count
}

func (s *Store) revokeUserCredentialsLocked(userID, workspaceID string, at time.Time) {
	for id, pat := range s.pats {
		if pat.UserID == userID && pat.RevokedAt == nil && (workspaceID == "" || pat.WorkspaceID == workspaceID) {
			pat.RevokedAt = cloneTime(&at)
			s.pats[id] = clonePAT(pat)
		}
	}
	for id, grant := range s.oauthGrants {
		if grant.UserID == userID && grant.RevokedAt == nil && (workspaceID == "" || grant.WorkspaceID == workspaceID) {
			grant.RevokedAt = cloneTime(&at)
			s.oauthGrants[id] = cloneOAuthGrant(grant)
		}
	}
	for id, token := range s.oauthAccessTokens {
		if token.UserID == userID && token.RevokedAt == nil && (workspaceID == "" || token.WorkspaceID == workspaceID) {
			token.RevokedAt = cloneTime(&at)
			s.oauthAccessTokens[id] = cloneOAuthAccessToken(token)
		}
	}
	for id, token := range s.oauthRefreshTokens {
		if token.UserID == userID && token.RevokedAt == nil && (workspaceID == "" || token.WorkspaceID == workspaceID) {
			token.RevokedAt = cloneTime(&at)
			s.oauthRefreshTokens[id] = cloneOAuthRefreshToken(token)
		}
	}
}

func yieldMemoryPage[T any](values []T, limit int, key func(T) (time.Time, string), yield func(credbound.PageEvent[T], error) bool) {
	hasMore := len(values) > limit
	if hasMore {
		values = values[:limit]
	}
	for _, value := range values {
		if !yield(credbound.ItemEvent(value), nil) {
			return
		}
	}
	end := credbound.PageEnd{HasMore: hasMore}
	if hasMore && len(values) > 0 {
		at, id := key(values[len(values)-1])
		end.NextCursor = encodeCursor(at, id)
	}
	yield(credbound.EndEvent[T](end), nil)
}

func cloneEmail(value credbound.EmailAddress) credbound.EmailAddress {
	value.VerifiedAt = cloneTime(value.VerifiedAt)
	return value
}

func cloneEmailVerification(value credbound.EmailVerificationCredential) credbound.EmailVerificationCredential {
	value.Digest = slices.Clone(value.Digest)
	return value
}

func cloneSSOIdentity(value credbound.SSOIdentity) credbound.SSOIdentity {
	value.LastUsedAt = cloneTime(value.LastUsedAt)
	return value
}

func cloneTOTP(value credbound.TOTPFactor) credbound.TOTPFactor {
	value.EncryptedSecret = slices.Clone(value.EncryptedSecret)
	return value
}

func cloneRecovery(values []credbound.RecoveryCode) []credbound.RecoveryCode {
	result := make([]credbound.RecoveryCode, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Digest = slices.Clone(value.Digest)
		result[index].UsedAt = cloneTime(value.UsedAt)
	}
	return result
}

func clonePasskey(value credbound.Passkey) credbound.Passkey {
	value.CredentialID = slices.Clone(value.CredentialID)
	value.CredentialJSON = slices.Clone(value.CredentialJSON)
	value.LastUsedAt = cloneTime(value.LastUsedAt)
	return value
}

func cloneSession(value credbound.Session) credbound.Session {
	value.Digest = slices.Clone(value.Digest)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

// revokeUserSessionsLocked backs both RevokeUserSessions and the session
// revocation cascade of CompletePasswordReset, SetUserDisabled and
// RevokeUserCredentials.
func (s *Store) revokeUserSessionsLocked(userID string, at time.Time) {
	for id, session := range s.sessions {
		if session.UserID == userID && session.RevokedAt == nil {
			session.RevokedAt = cloneTime(&at)
			s.sessions[id] = session
		}
	}
}

func clonePAT(value credbound.PAT) credbound.PAT {
	value.Digest = slices.Clone(value.Digest)
	value.Scopes = slices.Clone(value.Scopes)
	value.ExpiresAt = cloneTime(value.ExpiresAt)
	value.LastUsedAt = cloneTime(value.LastUsedAt)
	value.RevokedAt = cloneTime(value.RevokedAt)
	return value
}

func cloneWorkspaceDomain(value credbound.WorkspaceDomain) credbound.WorkspaceDomain {
	value.ConfirmedAt = cloneTime(value.ConfirmedAt)
	return value
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func normalizeMembership(value credbound.Membership) credbound.Membership {
	if value.Status == "" {
		value.Status = credbound.MembershipActive
	}
	if value.ProvisioningSource == "" {
		value.ProvisioningSource = credbound.ProvisioningSourceLocal
	}
	return value
}

var _ credbound.Store = (*Store)(nil)
var _ credbound.SCIMStore = (*Store)(nil)
var _ credbound.SignupStore = (*Store)(nil)
var _ credbound.SessionStore = (*Store)(nil)
var _ credbound.DomainStore = (*Store)(nil)

var _ credbound.OAuthStore = (*Store)(nil)
