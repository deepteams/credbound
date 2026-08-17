package credbound

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SignUp registers an anonymous visitor: one store transaction creates the
// user, their primary email address, their password credential, their
// workspace and their admin membership, with no instance role. It requires
// Config.SignUp and a SignupStore-capable store; otherwise it returns
// ErrNotSupported. The primary address starts unverified and the result
// carries the IssuedEmailVerification token the host delivers — the account
// cannot authenticate by email address until ConfirmEmail proves it. With
// Config.SignUp.AutoVerifyEmail the address is verified immediately and the
// result instead carries an AAL1 password Authentication.
//
// When the address already belongs to an account the call performs the same
// hashing and identifier generation, audits the collision, and returns
// SignUpResult{ExistingAccount: true} with no error, so the host answers the
// end user identically and may deliver an "already registered" notice to the
// address instead of a verification token.
func (m *Manager) SignUp(ctx context.Context, input SignUpInput) (_ SignUpResult, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "auth.signup", started, err) }()
	if m.signup == nil || m.signupStore == nil {
		return SignUpResult{}, ErrNotSupported
	}
	email, err := validEmail(input.Email)
	if err != nil {
		return SignUpResult{}, err
	}
	displayName := strings.TrimSpace(input.DisplayName)
	if displayName == "" {
		return SignUpResult{}, &ValidationError{Field: "display_name", Rule: "required", Message: "display name is required"}
	}
	workspaceName := strings.TrimSpace(input.WorkspaceName)
	if workspaceName == "" {
		return SignUpResult{}, &ValidationError{Field: "workspace_name", Rule: "required", Message: "workspace name is required"}
	}
	if err := m.validatePassword(ctx, input.Password); err != nil {
		return SignUpResult{}, err
	}
	// The hash, the identifiers and the verification secret are always
	// derived before the address is checked, so a taken address performs the
	// same work as a fresh one and timing reveals nothing.
	hash, err := m.passwords.Hash(input.Password)
	if err != nil {
		return SignUpResult{}, fmt.Errorf("hash password: %w", err)
	}
	userID, err := m.newID()
	if err != nil {
		return SignUpResult{}, err
	}
	emailID, err := m.newID()
	if err != nil {
		return SignUpResult{}, err
	}
	workspaceID, err := m.newID()
	if err != nil {
		return SignUpResult{}, err
	}
	rawToken := ""
	var verification *EmailVerificationCredential
	now := m.now()
	if !m.signup.AutoVerifyEmail {
		secret, secretErr := randomBytes(m.random, 32)
		if secretErr != nil {
			return SignUpResult{}, secretErr
		}
		rawToken = emailVerificationPrefix + "_" + emailID + "_" + base64.RawURLEncoding.EncodeToString(secret)
		verification = &EmailVerificationCredential{
			EmailID: emailID, Digest: m.tokenDigest("email-verification:" + rawToken), ExpiresAt: now.Add(m.emailVerificationTTL),
		}
	}
	existing, lookupErr := m.store.UserByEmail(ctx, email)
	if lookupErr == nil {
		return m.signUpCollision(ctx, existing.ID)
	}
	if !errors.Is(lookupErr, ErrNotFound) {
		return SignUpResult{}, lookupErr
	}
	user := User{ID: userID, Email: email, DisplayName: displayName, CreatedAt: now, UpdatedAt: now}
	primaryEmail := EmailAddress{ID: emailID, UserID: userID, Address: email, Primary: true, CreatedAt: now, UpdatedAt: now}
	if m.signup.AutoVerifyEmail {
		primaryEmail.VerifiedAt = cloneTime(&now)
	}
	workspace := Workspace{ID: workspaceID, Name: workspaceName, CreatedAt: now, UpdatedAt: now}
	membership := Membership{WorkspaceID: workspaceID, UserID: userID, Role: RoleAdmin, Status: MembershipActive, ProvisioningSource: ProvisioningSourceLocal, CreatedAt: now, UpdatedAt: now}
	event, err := m.newAudit(ctx, userID, "signup", "workspace", workspaceID, workspaceID, AuditSucceeded, "")
	if err != nil {
		return SignUpResult{}, err
	}
	userMeta, err := m.newEventMeta(EventUserCreated, "auth.signup", userID, workspaceID, event)
	if err != nil {
		return SignUpResult{}, err
	}
	workspaceMeta, err := m.newEventMeta(EventWorkspaceCreated, "auth.signup", userID, workspaceID, event)
	if err != nil {
		return SignUpResult{}, err
	}
	signupMeta, err := m.newEventMeta(EventSignUpCompleted, "auth.signup", userID, workspaceID, event)
	if err != nil {
		return SignUpResult{}, err
	}
	userChange := UserCreateChange{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	workspaceChange := WorkspaceCreateChange{EventMeta: workspaceMeta, Workspace: workspace, Owner: membership}
	commit := Commit{Audit: event, Transactional: func(ctx context.Context, tx Tx) error {
		if err := m.events.apply(ctx, "user.create", func(hook TransactionHook) error {
			return hook.ApplyUserCreate(ctx, tx, userChange)
		}); err != nil {
			return err
		}
		return m.events.apply(ctx, "workspace.create", func(hook TransactionHook) error {
			return hook.ApplyWorkspaceCreate(ctx, tx, workspaceChange)
		})
	}}
	if err := m.signupStore.CreateSignup(ctx, user, primaryEmail, verification, PasswordCredential{UserID: userID, Hash: hash, UpdatedAt: now}, workspace, membership, commit); err != nil {
		if errors.Is(err, ErrConflict) {
			// Another registration (or an unverified account invisible to
			// UserByEmail) claimed the address first: report it exactly like
			// the lookup collision. The existing owner is unknown here, so
			// the audit carries no actor.
			return m.signUpCollision(ctx, "")
		}
		return SignUpResult{}, m.mapStoreError(ctx, "auth.signup", err)
	}
	userEvent := UserCreatedEvent{EventMeta: userMeta, User: user, Email: primaryEmail, Membership: membership}
	workspaceEvent := WorkspaceCreatedEvent{EventMeta: workspaceMeta, Workspace: workspace, Owner: membership}
	signupEvent := SignUpCompletedEvent{EventMeta: signupMeta, User: user, Workspace: workspace}
	m.events.emit(ctx, EventUserCreated, func(listener EventListener) error { return listener.OnUserCreated(ctx, userEvent) })
	m.events.emit(ctx, EventWorkspaceCreated, func(listener EventListener) error { return listener.OnWorkspaceCreated(ctx, workspaceEvent) })
	m.events.emit(ctx, EventSignUpCompleted, func(listener EventListener) error { return listener.OnSignUpCompleted(ctx, signupEvent) })
	result := SignUpResult{User: user, Workspace: workspace}
	if m.signup.AutoVerifyEmail {
		result.Authentication = Authentication{UserID: userID, Method: MethodPassword, Level: AAL1, AuthenticatedAt: now}
	} else {
		result.EmailVerification = IssuedEmailVerification{Email: primaryEmail, Token: rawToken}
	}
	return result, nil
}

// signUpCollision audits a registration against a taken address and returns
// the outwardly successful result the host relays to the end user.
func (m *Manager) signUpCollision(ctx context.Context, ownerID string) (SignUpResult, error) {
	if auditErr := m.appendAuthenticationAudit(ctx, ownerID, "signup", AuditFailed, "email_taken"); auditErr != nil {
		return SignUpResult{}, auditErr
	}
	return SignUpResult{ExistingAccount: true}, nil
}
