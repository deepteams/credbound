package credbound_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/memory"
)

type bootstrapHook struct {
	credbound.UnimplementedTransactionHook
	calls  []string
	leaked credbound.Tx
	reject error
	panic  bool
}

func (h *bootstrapHook) ApplyUserCreate(_ context.Context, tx credbound.Tx, change credbound.UserCreateChange) error {
	h.calls = append(h.calls, string(change.Name))
	h.leaked = tx
	if h.panic {
		panic("hook panic")
	}
	return h.reject
}

func (h *bootstrapHook) ApplyWorkspaceCreate(_ context.Context, tx credbound.Tx, change credbound.WorkspaceCreateChange) error {
	h.calls = append(h.calls, string(change.Name))
	h.leaked = tx
	return h.reject
}

type eventRecorder struct {
	credbound.UnimplementedEventListener
	names []credbound.EventName
	metas []credbound.EventMeta
}

func (l *eventRecorder) record(meta credbound.EventMeta) {
	l.names = append(l.names, meta.Name)
	l.metas = append(l.metas, meta)
}

func (l *eventRecorder) OnUserCreated(_ context.Context, event credbound.UserCreatedEvent) error {
	l.record(event.EventMeta)
	return nil
}

func (l *eventRecorder) OnWorkspaceCreated(_ context.Context, event credbound.WorkspaceCreatedEvent) error {
	l.record(event.EventMeta)
	return nil
}

func (l *eventRecorder) OnBootstrapCompleted(_ context.Context, event credbound.BootstrapCompletedEvent) error {
	l.record(event.EventMeta)
	return nil
}

func (l *eventRecorder) OnPATCreated(_ context.Context, event credbound.PATCreatedEvent) error {
	l.record(event.EventMeta)
	return nil
}

type failingListener struct {
	credbound.UnimplementedEventListener
	panic bool
}

func (l failingListener) OnUserCreated(context.Context, credbound.UserCreatedEvent) error {
	if l.panic {
		panic("listener panic")
	}
	return errors.New("listener failed")
}

type stepUpRecorder struct {
	credbound.UnimplementedEventListener
	events []credbound.StepUpDeniedEvent
}

func (l *stepUpRecorder) OnStepUpDenied(_ context.Context, event credbound.StepUpDeniedEvent) error {
	l.events = append(l.events, event)
	return nil
}

type patRejectingHook struct {
	credbound.UnimplementedTransactionHook
	leaked credbound.Tx
}

func (h *patRejectingHook) ApplyPATCreation(_ context.Context, tx credbound.Tx, _ credbound.PATCreation) error {
	h.leaked = tx
	return errors.New("credits unavailable")
}

func TestBootstrapHooksRollbackAndTransactionLifetime(t *testing.T) {
	f := newFixture(t)
	hook := &bootstrapHook{reject: errors.New("workspace provisioning failed")}
	subscription := f.manager.AddTransactionHook(hook)

	_, _, err := f.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "root@example.com", DisplayName: "Root", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("bootstrap hook error = %v", err)
	}
	if !reflect.DeepEqual(hook.calls, []string{string(credbound.EventUserCreated)}) {
		t.Fatalf("hook calls before rejection = %#v", hook.calls)
	}
	if tx, ok := memory.TxFrom(hook.leaked); ok || tx != nil {
		t.Fatal("memory transaction remained usable after hook return")
	}
	if _, err := f.store.UserByEmail(context.Background(), "root@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("rejected bootstrap persisted its user: %v", err)
	}
	if events := collectAuditPage(t, f.store.InstanceAuditEvents(context.Background(), credbound.PageRequest{Limit: 50})); len(events.items) != 0 {
		t.Fatalf("rejected bootstrap persisted %d audit events", len(events.items))
	}

	subscription.Remove()
	subscription.Remove()
	f.bootstrap(t)

	panicFixture := newFixture(t)
	panicFixture.manager.AddTransactionHook(&bootstrapHook{panic: true})
	_, _, err = panicFixture.manager.Bootstrap(context.Background(), credbound.BootstrapInput{
		Email: "panic@example.com", DisplayName: "Panic", Password: "correct horse battery", WorkspaceName: "Main",
	})
	if !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("panicking hook error = %v", err)
	}
	if _, err := panicFixture.store.UserByEmail(context.Background(), "panic@example.com"); !errors.Is(err, credbound.ErrNotFound) {
		t.Fatalf("panicking hook persisted its user: %v", err)
	}
}

func TestBootstrapEventOrderAndListenerIsolation(t *testing.T) {
	f := newFixture(t)
	hook := &bootstrapHook{}
	recorder := &eventRecorder{}
	f.manager.AddTransactionHook(hook)
	f.manager.AddEventListener(failingListener{})
	f.manager.AddEventListener(failingListener{panic: true})
	f.manager.AddEventListener(recorder)

	authn, workspace := f.bootstrap(t)
	if !reflect.DeepEqual(hook.calls, []string{string(credbound.EventUserCreated), string(credbound.EventWorkspaceCreated)}) {
		t.Fatalf("bootstrap hook order = %#v", hook.calls)
	}
	want := []credbound.EventName{credbound.EventUserCreated, credbound.EventWorkspaceCreated, credbound.EventBootstrapCompleted}
	if !reflect.DeepEqual(recorder.names, want) {
		t.Fatalf("bootstrap event order = %#v", recorder.names)
	}
	ids := make(map[string]struct{}, len(recorder.metas))
	for _, meta := range recorder.metas {
		if !uuidV7.MatchString(meta.ID) || meta.AuditID == "" || meta.ActorID != authn.UserID || meta.WorkspaceID != workspace.ID {
			t.Fatalf("invalid bootstrap event metadata: %#v", meta)
		}
		ids[meta.ID] = struct{}{}
	}
	if len(ids) != len(recorder.metas) {
		t.Fatal("bootstrap events did not receive distinct UUIDv7 identifiers")
	}
}

func TestSubscriptionRemovalAndStepUpDeniedEvent(t *testing.T) {
	f := newFixture(t)
	removed := &eventRecorder{}
	subscription := f.manager.AddEventListener(removed)
	subscription.Remove()
	subscription.Remove()
	f.manager.AddEventListener(nil).Remove()
	f.manager.AddTransactionHook(nil).Remove()

	authn, _ := f.bootstrap(t)
	if len(removed.names) != 0 {
		t.Fatalf("removed listener received events: %#v", removed.names)
	}
	recorder := &stepUpRecorder{}
	f.manager.AddEventListener(recorder)
	_, err := f.manager.CreatePAT(context.Background(), authn, credbound.CreatePATInput{Name: "automation", Scopes: []string{"read"}})
	if !errors.Is(err, credbound.ErrStepUpRequired) {
		t.Fatalf("AAL1 PAT creation = %v", err)
	}
	if len(recorder.events) != 1 || recorder.events[0].Operation != "auth.pat.create" || recorder.events[0].UserID != authn.UserID || !uuidV7.MatchString(recorder.events[0].ID) {
		t.Fatalf("step-up event = %#v", recorder.events)
	}
}

func TestPATTransactionHookRollsBackMutationAndAudit(t *testing.T) {
	f := newFixture(t)
	authn, workspace := f.bootstrap(t)
	hook := &patRejectingHook{}
	f.manager.AddTransactionHook(hook)
	events := &eventRecorder{}
	f.manager.AddEventListener(events)

	_, err := f.manager.CreatePAT(context.Background(), aal2(authn.UserID, f.now), credbound.CreatePATInput{
		Name: "freemium", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if !errors.Is(err, credbound.ErrTransactionRejected) {
		t.Fatalf("PAT hook rejection = %v", err)
	}
	if tx, ok := memory.TxFrom(hook.leaked); ok || tx != nil {
		t.Fatal("rejected PAT retained an active transaction")
	}
	page := collectPage(t, f.store.PATs(context.Background(), authn.UserID, credbound.PageRequest{Limit: 50}))
	if len(page.items) != 0 {
		t.Fatalf("rejected PAT was persisted: %#v", page.items)
	}
	if len(events.names) != 0 {
		t.Fatalf("post-commit event emitted after rollback: %#v", events.names)
	}
}
