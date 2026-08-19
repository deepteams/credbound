package credbound_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/deepteams/credbound"
	"github.com/deepteams/credbound/credboundtest"
)

// The PRD's definition of done states that no secret appears in logs, errors
// or OTEL attributes, and the security principles promise the same of the
// audit trail. Nothing verified it beyond one assertion on the OAuth audit
// records. The two tests below close that gap from both ends: a runtime sweep
// that mints every kind of credential and then searches everything the library
// hands to a host for those exact values, and a structural check over the
// event payloads a listener forwards to third parties.

// recordingObserver captures every Operation the Manager reports.
type recordingObserver struct {
	mu         sync.Mutex
	operations []credbound.Operation
}

func (o *recordingObserver) Observe(_ context.Context, operation credbound.Operation) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.operations = append(o.operations, operation)
}

func (o *recordingObserver) strings() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	observed := make([]string, 0, len(o.operations))
	for _, operation := range o.operations {
		observed = append(observed, operation.Name+" "+operation.Outcome+" "+operation.Duration.String())
	}
	return observed
}

// TestNoSecretReachesLogsErrorsOrAudit mints one of every credential the
// library issues, then asserts that none of their raw values appears in the
// observability record, in a returned error, in the audit trail, or in the
// listings and export an administration UI reads.
func TestNoSecretReachesLogsErrorsOrAudit(t *testing.T) {
	observer := &recordingObserver{}
	clock := credboundtest.NewClock(credboundtest.DefaultStartTime)
	manager := credboundtest.NewManager(t,
		credboundtest.WithClock(clock),
		credboundtest.WithConfig(func(cfg *credbound.Config) {
			cfg.Observer = observer
			cfg.Passkeys = credboundtest.DiscoverablePasskeys{}
			cfg.SignUp = &credbound.SignUpConfig{AutoVerifyEmail: true}
		}))
	ctx := context.Background()
	root, workspace := credboundtest.Bootstrap(t, manager)

	// secrets collects every value that must never be observable again.
	secrets := map[string]string{
		"bootstrap password": credboundtest.BootstrapPassword,
		"TOTP secret":        "CREDBOUNDTESTSECRET",
	}
	add := func(label, value string) {
		t.Helper()
		if value == "" {
			t.Fatalf("%s was not issued", label)
		}
		secrets[label] = value
	}
	// observed collects everything the library hands back to the host.
	var observed []string
	record := func(label string, values ...string) {
		for _, value := range values {
			observed = append(observed, label+": "+value)
		}
	}
	recordError := func(label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s unexpectedly succeeded", label)
		}
		record("error "+label, err.Error())
	}

	stepUp := func() credbound.Authentication { return credboundtest.AAL2(root.UserID, clock.Now()) }

	pat, err := manager.CreatePAT(ctx, stepUp(), credbound.CreatePATInput{
		Name: "ci", WorkspaceID: workspace.ID, Scopes: []string{"read"},
	})
	if err != nil {
		t.Fatalf("create pat: %v", err)
	}
	add("PAT", pat.Token)

	session, err := manager.CreateSession(ctx, stepUp(), credbound.CreateSessionInput{})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	add("session token", session.Token)

	verification, err := manager.BeginEmailAddition(ctx, stepUp(), "second@example.com")
	if err != nil {
		t.Fatalf("begin email addition: %v", err)
	}
	add("email verification token", verification.Token)

	link, err := manager.BeginEmailAuthentication(ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin magic link: %v", err)
	}
	add("magic link token", link.Token)

	otp, err := manager.BeginEmailOTP(ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin otp: %v", err)
	}
	add("OTP continuation", otp.Continuation)

	if _, err := manager.BeginTOTPEnrollment(ctx, stepUp()); err != nil {
		t.Fatalf("begin totp: %v", err)
	}
	recovery, err := manager.ConfirmTOTPEnrollment(ctx, stepUp(), credboundtest.ValidTOTPCode)
	if err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	for index, code := range recovery {
		add(fmt.Sprintf("recovery code %d", index), code)
	}

	invitation, err := manager.InviteToWorkspace(ctx, stepUp(), workspace.ID, credbound.InviteToWorkspaceInput{
		Email: "invitee@example.com", Role: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	add("invitation token", invitation.Token)

	scim, err := manager.CreateSCIMConfiguration(ctx, stepUp(), workspace.ID, credbound.CreateSCIMConfigurationInput{
		DefaultRole: credbound.RoleMember,
	})
	if err != nil {
		t.Fatalf("create scim configuration: %v", err)
	}
	add("SCIM credential", scim.Token)

	reset, err := manager.BeginPasswordReset(ctx, credboundtest.BootstrapEmail)
	if err != nil {
		t.Fatalf("begin reset: %v", err)
	}
	add("password reset token", reset.Token)

	// Failing paths are where a careless implementation echoes the input it
	// rejected, so every public error is collected too.
	_, err = manager.AuthenticatePassword(ctx, credboundtest.BootstrapEmail, credboundtest.BootstrapPassword+"!")
	recordError("wrong password", err)
	_, err = manager.AuthenticatePAT(ctx, pat.Token+"tampered")
	recordError("tampered pat", err)
	_, _, err = manager.AuthenticateSession(ctx, session.Token+"tampered")
	recordError("tampered session", err)
	_, err = manager.ConfirmEmail(ctx, verification.Token+"tampered")
	recordError("tampered verification", err)
	_, err = manager.CompleteEmailOTP(ctx, otp.Continuation, "000000")
	recordError("wrong otp", err)
	_, err = manager.CompletePasswordReset(ctx, reset.Token+"tampered", "another correct horse battery")
	recordError("tampered reset", err)
	_, err = manager.VerifyTOTP(ctx, credboundtest.AAL2(root.UserID, clock.Now()), "000000")
	recordError("wrong totp", err)
	_, err = manager.AuthenticateSCIM(ctx, scim.Token+"tampered")
	recordError("tampered scim credential", err)

	// Everything a host can read back: the audit trail, the listings an
	// administration UI shows, and the data-subject export.
	for event, err := range manager.InstanceAuditEvents(ctx, stepUp(), credbound.PageRequest{Limit: 100}) {
		if err != nil {
			t.Fatalf("instance audit: %v", err)
		}
		if event.Data != nil {
			record("audit", marshal(t, *event.Data))
		}
	}
	for event, err := range manager.PATs(ctx, stepUp(), root.UserID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatalf("pats: %v", err)
		}
		if event.Data != nil {
			record("pat listing", marshal(t, *event.Data))
		}
	}
	for event, err := range manager.Sessions(ctx, stepUp(), root.UserID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatalf("sessions: %v", err)
		}
		if event.Data != nil {
			record("session listing", marshal(t, *event.Data))
		}
	}
	for value, err := range manager.SCIMCredentials(ctx, stepUp(), scim.Configuration.ID) {
		if err != nil {
			t.Fatalf("scim credentials: %v", err)
		}
		record("scim credential listing", marshal(t, value))
	}
	for event, err := range manager.WorkspaceInvitations(ctx, stepUp(), workspace.ID, credbound.PageRequest{Limit: 50}) {
		if err != nil {
			t.Fatalf("invitations: %v", err)
		}
		if event.Data != nil {
			record("invitation listing", marshal(t, *event.Data))
		}
	}
	export, err := manager.ExportUserData(ctx, stepUp(), root.UserID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	record("export", marshal(t, export))
	record("observability", observer.strings()...)

	if len(observer.operations) == 0 {
		t.Fatal("the observer recorded nothing, the sweep proves nothing")
	}
	for label, secret := range secrets {
		for _, line := range observed {
			if strings.Contains(line, secret) {
				t.Fatalf("the %s leaked into %s", label, line)
			}
		}
	}
}

// marshal renders a value with both its JSON and Go representations, so a
// secret hidden in an unexported-free struct field or a byte slice is visible
// to the scan either way.
func marshal(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		encoded = []byte(err.Error())
	}
	return string(encoded) + " " + fmt.Sprintf("%#v", value)
}

// secretFieldName matches the field names a credential would plausibly hide
// behind in an event payload, and identifierSuffix exempts the names that
// merely reference one — an identifier, a count, a timestamp — since those are
// exactly what an analytics payload is expected to carry.
var (
	secretFieldName = regexp.MustCompile(`(?i)(token|secret|password|passphrase|recovery|pepper|apikey|privatekey|credential)`)
	// Digest and Fingerprint name one-way derivations — Authentication's
	// CredentialDigest is a SHA-256 of an already-hashed credential — which
	// an analytics payload may legitimately carry; the raw values are what
	// this guard is about.
	identifierSuffix = regexp.MustCompile(`(ID|IDs|Count|At|Kind|Name|Method|Source|Status|Type|Digest|Fingerprint)$`)
)

// credentialShaped reports whether a field name suggests the payload carries
// the credential itself rather than a reference to it.
func credentialShaped(name string) bool {
	return secretFieldName.MatchString(name) && !identifierSuffix.MatchString(name)
}

// TestEventPayloadsCarryNoSecretField pins the analytics boundary: a listener
// forwards these payloads to Segment or a webhook, so no event may carry a raw
// credential. Rather than trusting a review of seventy-one payloads, this walks
// the EventListener interface itself, so a new event that adds a Token field
// fails here before it can ship.
func TestEventPayloadsCarryNoSecretField(t *testing.T) {
	listener := reflect.TypeOf((*credbound.EventListener)(nil)).Elem()
	if listener.NumMethod() < 2 {
		t.Fatalf("the event listener exposes %d methods", listener.NumMethod())
	}
	inspected := 0
	for index := range listener.NumMethod() {
		method := listener.Method(index)
		if !strings.HasPrefix(method.Name, "On") || method.Type.NumIn() != 2 {
			continue
		}
		payload := method.Type.In(1)
		if payload.Kind() != reflect.Struct {
			continue
		}
		inspected++
		walkEventFields(t, method.Name, payload, payload.Name(), 0)
	}
	if inspected == 0 {
		t.Fatal("no event payload was inspected")
	}
}

func walkEventFields(t *testing.T, event string, payload reflect.Type, path string, depth int) {
	t.Helper()
	if depth > 4 {
		return
	}
	for index := range payload.NumField() {
		field := payload.Field(index)
		if !field.IsExported() {
			continue
		}
		name := path + "." + field.Name
		if credentialShaped(field.Name) {
			t.Errorf("%s carries the credential-shaped field %s", event, name)
		}
		switch field.Type.Kind() {
		case reflect.Struct:
			if field.Type.PkgPath() == "time" {
				continue
			}
			walkEventFields(t, event, field.Type, name, depth+1)
		case reflect.Pointer, reflect.Slice:
			if element := field.Type.Elem(); element.Kind() == reflect.Struct && element.PkgPath() != "time" {
				walkEventFields(t, event, element, name+"[]", depth+1)
			}
		}
	}
}
