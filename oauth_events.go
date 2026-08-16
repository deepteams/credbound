package credbound

import (
	"context"
	"slices"
)

func (m *Manager) newOAuthChange(name EventName, operation string, audit AuditEvent, client OAuthClient, grantID, tokenID, resourceID, workspaceID string, scopes []string) (OAuthChange, Commit, error) {
	meta, err := m.newEventMeta(name, operation, audit.ActorID, workspaceID, audit)
	if err != nil {
		return OAuthChange{}, Commit{}, err
	}
	change := OAuthChange{
		EventMeta: meta, IssuerID: client.IssuerID, ClientID: client.ID, ClientSource: client.Source,
		GrantID: grantID, TokenID: tokenID, ResourceID: resourceID, Scopes: slices.Clone(scopes),
	}
	commit := m.transactionalCommit(audit, "oauth.change", func(ctx context.Context, tx Tx, hook TransactionHook) error {
		return hook.ApplyOAuthChange(ctx, tx, change)
	})
	return change, commit, nil
}

func (m *Manager) emitOAuthChange(ctx context.Context, change OAuthChange) {
	change.Scopes = slices.Clone(change.Scopes)
	m.events.emit(ctx, change.Name, func(listener EventListener) error {
		return listener.OnOAuthEvent(ctx, OAuthEvent{OAuthChange: change})
	})
}
