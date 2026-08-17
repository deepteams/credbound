package credbound

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type internalNoopHook struct{ UnimplementedTransactionHook }

type internalNoopListener struct{ UnimplementedEventListener }

func TestGeneratedNoopExtensions(t *testing.T) {
	UnimplementedTransactionHook{}.unimplementedTransactionHook()
	UnimplementedEventListener{}.unimplementedEventListener()
	for _, extension := range []any{UnimplementedTransactionHook{}, UnimplementedEventListener{}} {
		value := reflect.ValueOf(extension)
		for index := 0; index < value.NumMethod(); index++ {
			method := value.Method(index)
			arguments := make([]reflect.Value, method.Type().NumIn())
			for argument := range arguments {
				arguments[argument] = reflect.Zero(method.Type().In(argument))
			}
			results := method.Call(arguments)
			if len(results) != 1 || !results[0].IsNil() {
				t.Fatalf("no-op method %s returned %#v", value.Type().Method(index).Name, results)
			}
		}
	}
}

func TestEventRegistryErrorBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	var nilHook *internalNoopHook
	if _, err := newEventRegistry(nopObserver{}, func() time.Time { return now }, []TransactionHook{nilHook}, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("typed nil hook = %v", err)
	}
	var nilListener *internalNoopListener
	if _, err := newEventRegistry(nopObserver{}, func() time.Time { return now }, nil, []EventListener{nilListener}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("typed nil listener = %v", err)
	}

	if err, panicked := safeEventCall(func() error { return nil }); err != nil || panicked {
		t.Fatalf("successful callback = %v, panic=%v", err, panicked)
	}
	boom := errors.New("boom")
	if err, panicked := safeEventCall(func() error { return boom }); !errors.Is(err, boom) || panicked {
		t.Fatalf("failed callback = %v, panic=%v", err, panicked)
	}
	if err, panicked := safeEventCall(func() error { panic("boom") }); err == nil || !panicked {
		t.Fatalf("panicking callback = %v, panic=%v", err, panicked)
	}
	if callbackOutcome(nil, true) != "panic" || callbackOutcome(boom, false) != "error" || callbackOutcome(nil, false) != "success" {
		t.Fatal("callback outcomes are incorrect")
	}
	if mapTransactionError(nil) != nil {
		t.Fatal("nil transaction error was changed")
	}
	for _, sentinel := range []error{ErrConflict, context.Canceled, context.DeadlineExceeded} {
		if !errors.Is(mapTransactionError(sentinel), sentinel) {
			t.Fatalf("transaction sentinel was hidden: %v", sentinel)
		}
	}
	if err := mapTransactionError(boom); !errors.Is(err, ErrTransactionRejected) || errors.Is(err, boom) {
		t.Fatalf("generic transaction error = %v", err)
	}
	if clonePATExpiration(nil) != nil {
		t.Fatal("nil PAT expiration was not preserved")
	}
	expires := now.Add(time.Hour)
	cloned := clonePATExpiration(&expires)
	if cloned == nil || cloned == &expires || !cloned.Equal(expires) {
		t.Fatal("PAT expiration was not cloned")
	}
	var subscription *eventSubscription
	subscription.Remove()
}

func TestUUIDv7SequenceOverflowAndClockRollback(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	m := &Manager{clock: func() time.Time { return now }, random: bytes.NewReader(make([]byte, 16*4100))}
	previous := ""
	for range 4097 {
		id, err := m.newID()
		if err != nil {
			t.Fatal(err)
		}
		if previous != "" && id <= previous {
			t.Fatalf("UUIDv7 is not monotonic: %q <= %q", id, previous)
		}
		previous = id
	}
	if m.idUnixMilli != now.UnixMilli()+1 || m.idSequence != 0 {
		t.Fatalf("sequence overflow state = (%d, %d)", m.idUnixMilli, m.idSequence)
	}
	now = now.Add(-time.Hour)
	if _, err := m.newID(); err != nil || m.idUnixMilli != time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC).UnixMilli()+1 || m.idSequence != 1 {
		t.Fatalf("clock rollback state = (%d, %d), err=%v", m.idUnixMilli, m.idSequence, err)
	}
}

func TestContinuationAndEncryptionBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	m := &Manager{
		secretKey: bytes.Repeat([]byte{1}, 32), sealKey: bytes.Repeat([]byte{1}, 32),
		clock:  func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{2}, 256)),
	}
	continuation, err := m.encodeContinuation(ceremonyContinuation{
		UserID: "user", Operation: "register", ExpiresAt: now.Add(time.Minute), Session: []byte("session"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.decodeContinuation(continuation, "authenticate"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong operation = %v", err)
	}

	invalidJSON, err := m.seal([]byte("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.decodeContinuation(base64.RawURLEncoding.EncodeToString(invalidJSON), "register"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid JSON continuation = %v", err)
	}
	emptyUser, err := m.encodeContinuation(ceremonyContinuation{Operation: "register", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.decodeContinuation(emptyUser, "register"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("empty user continuation = %v", err)
	}

	sealed, err := m.seal([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := m.open(sealed); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("tampered ciphertext = %v", err)
	}
	if _, err := m.open([]byte("short")); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("short ciphertext = %v", err)
	}
}

func TestSSOContinuationBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	m := &Manager{
		secretKey: bytes.Repeat([]byte{1}, 32), sealKey: bytes.Repeat([]byte{1}, 32), clock: func() time.Time { return now },
		random: bytes.NewReader(bytes.Repeat([]byte{2}, 512)),
	}
	valid := ssoContinuation{
		ProviderConfigurationID: "0198b463-0000-7000-8000-000000000001",
		Operation:               ssoLogin, ExpiresAt: now.Add(time.Minute), Session: []byte("session"),
	}
	encoded, err := m.encodeSSOContinuation(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.decodeSSOContinuation("%%%"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid SSO base64 = %v", err)
	}
	tampered := encoded[:len(encoded)-1] + "A"
	if tampered == encoded {
		tampered = encoded[:len(encoded)-1] + "B"
	}
	if _, err := m.decodeSSOContinuation(tampered); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("tampered SSO continuation = %v", err)
	}
	invalidJSON, err := m.seal([]byte("not-json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.decodeSSOContinuation(base64.RawURLEncoding.EncodeToString(invalidJSON)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("invalid SSO JSON = %v", err)
	}
	cases := []ssoContinuation{
		{ProviderConfigurationID: "0198b463-0000-4000-8000-000000000001", Operation: ssoLogin, ExpiresAt: now.Add(time.Minute), Session: []byte("session")},
		{ProviderConfigurationID: valid.ProviderConfigurationID, Operation: ssoLogin, ExpiresAt: now.Add(time.Minute)},
		{ProviderConfigurationID: valid.ProviderConfigurationID, Operation: "unknown", ExpiresAt: now.Add(time.Minute), Session: []byte("session")},
		{ProviderConfigurationID: valid.ProviderConfigurationID, Operation: ssoLink, ExpiresAt: now.Add(time.Minute), Session: []byte("session")},
		{ProviderConfigurationID: valid.ProviderConfigurationID, Operation: ssoLogin, ExpiresAt: now, Session: []byte("session")},
	}
	for _, state := range cases {
		encoded, err := m.encodeSSOContinuation(state)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.decodeSSOContinuation(encoded); err == nil {
			t.Fatalf("invalid SSO continuation accepted: %#v", state)
		}
	}
}

func TestAdminPermissionAndValueHelpers(t *testing.T) {
	permissions, err := buildAdminPermissions(map[InstanceRole][]Permission{
		InstanceRoleDeveloper: {PermissionAdminAccess},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := &Manager{adminPermissions: permissions}
	if !m.hasAdminPermission(InstanceRoleDeveloper, PermissionAdminAccess) || m.hasAdminPermission(InstanceRoleDeveloper, PermissionSettingsWrite) {
		t.Fatal("permission override was not restrictive")
	}
	if m.hasAdminPermission(InstanceRole("unknown"), PermissionAdminAccess) {
		t.Fatal("unknown role has permissions")
	}
	if _, err := buildAdminPermissions(map[InstanceRole][]Permission{InstanceRole("unknown"): {PermissionAdminAccess}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown admin role = %v", err)
	}

	authn := Authentication{Scopes: []string{"*"}}
	if !authn.HasScope("") || !authn.HasScope("anything") {
		t.Fatal("wildcard or empty scope was rejected")
	}
	now := time.Now()
	copy := cloneTime(&now)
	if copy == nil || !copy.Equal(now) || copy == &now || cloneTime(nil) != nil {
		t.Fatal("time cloning is unsafe")
	}
	roles, err := buildRoleCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	if roles.includes(Role("unknown"), RoleMember) || roles.allows(Role("unknown"), PermissionWorkspaceAccess) {
		t.Fatal("unknown workspace role was authorized")
	}
	if !errors.Is(mapAuditError(ErrAuditUnavailable), ErrAuditUnavailable) || mapAuditError(nil) != nil || mapAuditError(errors.New("other")).Error() != "other" {
		t.Fatal("audit error mapping is incorrect")
	}
	if normalizeRecoveryCode(" abcd- efgh ") != "ABCDEFGH" {
		t.Fatal("recovery code normalization is incorrect")
	}
	if _, ok := parsePAT("cbp_000000000000_" + strings.Repeat("*", 43)); ok {
		t.Fatal("invalid base64 PAT accepted")
	}
	nopObserver{}.Observe(context.Background(), Operation{})
}

func TestSCIMValueHelpers(t *testing.T) {
	validToken := "cbs_000000000000_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if prefix, ok := parseSCIMToken(validToken); !ok || prefix != "000000000000" {
		t.Fatalf("valid SCIM token = %q, %v", prefix, ok)
	}
	for _, token := range []string{
		"", "cbp_000000000000_" + strings.Repeat("a", 43), "cbs_short_" + strings.Repeat("a", 43),
		"cbs_zzzzzzzzzzzz_" + strings.Repeat("a", 43), "cbs_000000000000_***",
	} {
		if _, ok := parseSCIMToken(token); ok {
			t.Fatalf("invalid SCIM token accepted: %q", token)
		}
	}
	valid, primary, err := normalizeSCIMUserInput(SCIMUserInput{
		UserName: " User@Example.com ", Emails: []SCIMEmail{{Value: "one@example.com"}, {Value: "two@example.com"}}, Active: true,
	}, true)
	if err != nil || primary != "one@example.com" || !valid.Emails[0].Primary || valid.DisplayName != "user@example.com" {
		t.Fatalf("normalized SCIM user = %#v, %q, %v", valid, primary, err)
	}
	for name, input := range map[string]SCIMUserInput{
		"username":      {},
		"external":      {UserName: "user@example.com", ExternalID: strings.Repeat("x", 256), Emails: []SCIMEmail{{Value: "user@example.com"}}},
		"display":       {UserName: "user@example.com", DisplayName: strings.Repeat("x", 256), Emails: []SCIMEmail{{Value: "user@example.com"}}},
		"duplicate":     {UserName: "user@example.com", Emails: []SCIMEmail{{Value: "user@example.com"}, {Value: "USER@example.com"}}},
		"primaries":     {UserName: "user@example.com", Emails: []SCIMEmail{{Value: "one@example.com", Primary: true}, {Value: "two@example.com", Primary: true}}},
		"missing email": {UserName: "user@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := normalizeSCIMUserInput(input, true); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid SCIM user = %v", err)
			}
		})
	}
	group, err := normalizeSCIMGroupInput(SCIMGroupInput{
		ExternalID: " external ", DisplayName: " Group ",
		MemberIDs: []string{"0198b463-0000-7000-8000-000000000001", "0198b463-0000-7000-8000-000000000001"},
	})
	if err != nil || len(group.MemberIDs) != 1 || group.DisplayName != "Group" {
		t.Fatalf("normalized SCIM group = %#v, %v", group, err)
	}
	for _, group := range []SCIMGroupInput{
		{}, {DisplayName: strings.Repeat("x", 256)}, {DisplayName: "Group", ExternalID: strings.Repeat("x", 256)}, {DisplayName: "Group", MemberIDs: []string{"invalid"}},
	} {
		if _, err := normalizeSCIMGroupInput(group); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid SCIM group = %v", err)
		}
	}
	for _, filter := range []SCIMFilter{{}, {Attribute: "id"}, {Attribute: "externalId"}, {Attribute: "userName"}, {Attribute: "emails.value"}, {Attribute: "active"}} {
		if !validSCIMFilter(filter, true) {
			t.Fatalf("valid user filter rejected: %#v", filter)
		}
	}
	if validSCIMFilter(SCIMFilter{Attribute: "unknown"}, true) || validSCIMFilter(SCIMFilter{Attribute: "active"}, false) || !validSCIMFilter(SCIMFilter{Attribute: "displayName"}, false) {
		t.Fatal("SCIM filter validation mismatch")
	}
}

func TestKeySeparationLegacyFallback(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	legacy := &Manager{secretKey: raw, sealKey: raw, random: bytes.NewReader(bytes.Repeat([]byte{2}, 64))}
	sealed, err := legacy.seal([]byte("pre-separation data"))
	if err != nil {
		t.Fatal(err)
	}
	current := &Manager{
		secretKey: raw,
		sealKey:   bytes.Repeat([]byte{8}, 32),
		digestKey: bytes.Repeat([]byte{9}, 32),
		random:    bytes.NewReader(bytes.Repeat([]byte{2}, 64)),
	}
	plaintext, err := current.open(sealed)
	if err != nil || string(plaintext) != "pre-separation data" {
		t.Fatalf("legacy unseal = %q, %v", plaintext, err)
	}
	if !current.matchTokenDigest(digest(raw, "token"), "token") {
		t.Fatal("legacy digest rejected")
	}
	if !current.matchTokenDigest(current.tokenDigest("token"), "token") {
		t.Fatal("derived digest rejected")
	}
	if current.matchTokenDigest(current.tokenDigest("token"), "other") {
		t.Fatal("mismatched digest accepted")
	}
}
