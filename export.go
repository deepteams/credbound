package credbound

import (
	"context"
	"errors"
	"iter"
)

// WorkspaceMembership pairs a workspace with the exported user's membership in
// it. It is the workspace-affiliation entry of a UserDataExport.
type WorkspaceMembership struct {
	Workspace  Workspace
	Membership Membership
}

// UserDataExport is the structured copy of everything Credbound holds about one
// user, assembled for a data-subject access request (GDPR Article 15/20). It
// deliberately omits secrets — token digests and sealed passkey material are
// scrubbed — and the append-only audit log, which is retained under the host's
// security-log policy and read separately through AuditEvents. Sessions need a
// SessionStore-capable store, SCIMUsers and Invitations a PrivacyStore-capable
// one, and OAuthGrants the OAuth capability; the sections are empty otherwise.
type UserDataExport struct {
	User          User
	Emails        []EmailAddress
	Workspaces    []WorkspaceMembership
	SSOIdentities []SSOIdentity
	Passkeys      []Passkey
	PATs          []PAT
	Sessions      []Session
	// SCIMUsers are the tenant-scoped directory profiles provisioned for the
	// user, with the directory's own attributes included.
	SCIMUsers []SCIMUser
	// Invitations are the workspace invitations the user accepted; they carry
	// the address the user was invited under, which may predate a rename.
	Invitations []WorkspaceInvitation
	// OAuthGrants are the user's OAuth consents, revoked ones included.
	OAuthGrants []OAuthGrant
}

// ExportUserData gathers every record Credbound holds about a user into one
// document for a data-subject access request. An empty userID exports the
// actor's own data and needs only a recent interactive authentication;
// exporting another user requires a fresh AAL2 step-up and admin users read.
// Sessions are included only on a SessionStore-capable store, SCIM profiles
// and accepted workspace invitations only on a PrivacyStore-capable one, and
// OAuth grants only with the OAuth capability. Token digests, sealed passkey
// credentials and the audit log are never included; the audit log stays
// available through AuditEvents under its own retention policy.
func (m *Manager) ExportUserData(ctx context.Context, actor Authentication, userID string) (_ UserDataExport, err error) {
	started := m.now()
	defer func() { m.observe(ctx, "user.data.export", started, err) }()
	if actor.UserID == "" {
		return UserDataExport{}, ErrUnauthorized
	}
	if userID == "" {
		userID = actor.UserID
	}
	if userID == actor.UserID {
		if err := m.requireRecentInteractive(ctx, actor); err != nil {
			return UserDataExport{}, err
		}
	} else {
		if err := m.requireStepUp(ctx, actor, "user.data.export"); err != nil {
			return UserDataExport{}, err
		}
		if err := m.AuthorizeAdmin(ctx, actor, PermissionUsersRead); err != nil {
			return UserDataExport{}, err
		}
	}

	user, err := m.store.UserByID(ctx, userID)
	if err != nil {
		return UserDataExport{}, err
	}
	export := UserDataExport{User: user}

	if export.Emails, err = drainPages(func(page PageRequest) iter.Seq2[PageEvent[EmailAddress], error] {
		return m.store.Emails(ctx, userID, page)
	}); err != nil {
		return UserDataExport{}, err
	}

	workspaces, err := drainPages(func(page PageRequest) iter.Seq2[PageEvent[Workspace], error] {
		return m.store.UserWorkspaces(ctx, userID, page)
	})
	if err != nil {
		return UserDataExport{}, err
	}
	for _, workspace := range workspaces {
		membership, membershipErr := m.store.Membership(ctx, workspace.ID, userID)
		if membershipErr != nil {
			if errors.Is(membershipErr, ErrNotFound) {
				continue
			}
			return UserDataExport{}, membershipErr
		}
		export.Workspaces = append(export.Workspaces, WorkspaceMembership{Workspace: workspace, Membership: membership})
	}

	if export.SSOIdentities, err = drainPages(func(page PageRequest) iter.Seq2[PageEvent[SSOIdentity], error] {
		return m.store.SSOIdentities(ctx, userID, page)
	}); err != nil {
		return UserDataExport{}, err
	}

	for passkey, passkeyErr := range m.store.Passkeys(ctx, userID) {
		if passkeyErr != nil {
			return UserDataExport{}, passkeyErr
		}
		passkey.CredentialJSON = nil
		export.Passkeys = append(export.Passkeys, passkey)
	}

	if export.PATs, err = drainPages(func(page PageRequest) iter.Seq2[PageEvent[PAT], error] {
		return m.store.PATs(ctx, userID, page)
	}); err != nil {
		return UserDataExport{}, err
	}
	for index := range export.PATs {
		export.PATs[index].Digest = nil
	}

	if m.sessionStore != nil {
		if export.Sessions, err = drainPages(func(page PageRequest) iter.Seq2[PageEvent[Session], error] {
			return m.sessionStore.Sessions(ctx, userID, page)
		}); err != nil {
			return UserDataExport{}, err
		}
		for index := range export.Sessions {
			export.Sessions[index].Digest = nil
		}
	}

	if m.privacyStore != nil {
		for link, linkErr := range m.privacyStore.SCIMUsersByUser(ctx, userID) {
			if linkErr != nil {
				return UserDataExport{}, linkErr
			}
			export.SCIMUsers = append(export.SCIMUsers, link)
		}
		for invitation, invitationErr := range m.privacyStore.AcceptedWorkspaceInvitations(ctx, userID) {
			if invitationErr != nil {
				return UserDataExport{}, invitationErr
			}
			invitation.Digest = nil
			export.Invitations = append(export.Invitations, invitation)
		}
	}

	if m.oauthStore != nil {
		if export.OAuthGrants, err = drainPages(func(page PageRequest) iter.Seq2[PageEvent[OAuthGrant], error] {
			return m.oauthStore.OAuthGrants(ctx, userID, "", page)
		}); err != nil {
			return UserDataExport{}, err
		}
	}

	return export, nil
}

// drainPages reads every page of a cursor-paginated store query into a slice.
func drainPages[T any](query func(PageRequest) iter.Seq2[PageEvent[T], error]) ([]T, error) {
	var items []T
	cursor := ""
	for {
		next := ""
		more := false
		for event, err := range query(PageRequest{Cursor: cursor, Limit: 100}) {
			if err != nil {
				return nil, err
			}
			if event.Data != nil {
				items = append(items, *event.Data)
			}
			if event.End != nil {
				next, more = event.End.NextCursor, event.End.HasMore
			}
		}
		if !more || next == "" {
			return items, nil
		}
		cursor = next
	}
}
