package credbound

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type edgeReader struct {
	remaining int
	err       error
}

func (r *edgeReader) Read(target []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.err
	}
	count := min(len(target), r.remaining)
	for index := range count {
		target[index] = byte(index + 1)
	}
	r.remaining -= count
	if count < len(target) {
		return count, r.err
	}
	return count, nil
}

type valueSSOProvider struct{}

func (valueSSOProvider) ConfigurationID() string { return "0198b463-0000-7000-8000-000000000001" }
func (valueSSOProvider) Kind() SSOProviderKind   { return SSOProviderOIDC }
func (valueSSOProvider) Begin(context.Context, SSORequest) (SSOProviderChallenge, error) {
	return SSOProviderChallenge{}, nil
}
func (valueSSOProvider) Finish(context.Context, []byte, []byte) (SSOClaims, error) {
	return SSOClaims{}, nil
}

func TestInternalSecurityHelperEdges(t *testing.T) {
	if nilSSOProvider(valueSSOProvider{}) {
		t.Fatal("value SSO provider treated as nil")
	}
	var nilProvider *valueSSOProvider
	if !nilSSOProvider(nilProvider) {
		t.Fatal("typed nil SSO provider accepted")
	}
	nopObserver{}.Observe(t.Context(), Operation{})

	for _, invalid := range []string{
		"", "0198b463-0000-6000-8000-000000000001", "0198b463-0000-7000-7000-000000000001",
		"0198b463-0000-7000-8000-00000000000g",
	} {
		if validUUIDv7(invalid) {
			t.Fatalf("invalid UUIDv7 accepted: %q", invalid)
		}
	}

	boom := errors.New("random unavailable")
	manager := &Manager{secretKey: []byte("short"), sealKey: []byte("short"), random: &edgeReader{err: boom}, clock: func() time.Time { return time.Unix(1, 0) }}
	if _, err := manager.seal([]byte("payload")); err == nil {
		t.Fatal("invalid AES key accepted for sealing")
	}
	if _, err := manager.open([]byte("payload")); err == nil {
		t.Fatal("invalid AES key accepted for opening")
	}
	manager.secretKey = make([]byte, 32)
	manager.sealKey = make([]byte, 32)
	if _, err := manager.encodeContinuation(ceremonyContinuation{}); !errors.Is(err, boom) {
		t.Fatalf("continuation random failure = %v", err)
	}
	if _, err := manager.encodeOAuthContinuation(oauthAuthorizationContinuation{}); !errors.Is(err, boom) {
		t.Fatalf("OAuth continuation random failure = %v", err)
	}

	manager.oauth = &OAuthConfig{Pepper: make([]byte, 32)}
	manager.random = &edgeReader{err: boom}
	if _, _, err := manager.newOAuthBearer("test"); !errors.Is(err, boom) {
		t.Fatalf("bearer prefix failure = %v", err)
	}
	manager.random = &edgeReader{remaining: 6, err: boom}
	if _, _, err := manager.newOAuthBearer("test"); !errors.Is(err, boom) {
		t.Fatalf("bearer secret failure = %v", err)
	}

	validClient := OAuthClientRegistrationInput{
		Name: "Client", ApplicationType: OAuthApplicationWeb,
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: OAuthAuthNone,
	}
	manager.random = &edgeReader{err: boom}
	if _, _, err := manager.newOAuthClient(OAuthIssuer{}, OAuthClientPreRegistered, validClient, true); !errors.Is(err, boom) {
		t.Fatalf("client ID failure = %v", err)
	}
	validClient.TokenEndpointAuthMethod = OAuthAuthClientSecretBasic
	manager.random = &edgeReader{remaining: 16, err: boom}
	if _, _, err := manager.newOAuthClient(OAuthIssuer{}, OAuthClientPreRegistered, validClient, true); !errors.Is(err, boom) {
		t.Fatalf("client secret failure = %v", err)
	}
}

func TestOAuthURLSectorAndIdentifierEdges(t *testing.T) {
	for _, raw := range []string{
		"https://client.example.com/a%2Fb",
		"https://client.example.com/a%5Cb",
		"https://client.example.com/a/../b",
	} {
		if _, err := validateCIMDClientID(raw); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("CIMD identifier %q = %v", raw, err)
		}
	}
	if _, err := oauthSectorIdentifier([]string{"://bad"}, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid sector URI = %v", err)
	}
	if sector, err := oauthSectorIdentifier([]string{"custom:/callback"}, false); err != nil || sector != "" {
		t.Fatalf("hostless non-OIDC sector = %q, %v", sector, err)
	}
	if _, err := oauthSectorIdentifier([]string{"custom:/callback"}, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("hostless OIDC sector = %v", err)
	}
	if _, err := oauthSectorIdentifier([]string{"https://one.example/callback", "https://two.example/callback"}, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("multi-sector OIDC client = %v", err)
	}
	if sector, err := oauthSectorIdentifier(nil, false); err != nil || sector != "" {
		t.Fatalf("empty sector = %q, %v", sector, err)
	}
	if !strings.Contains(oauthReservedScopeDescription("custom"), "custom") {
		t.Fatal("custom scope description lost")
	}
}

func TestRandomReaderShortRead(t *testing.T) {
	boom := errors.New("short")
	if _, err := randomBytes(&edgeReader{remaining: 1, err: boom}, 2); !errors.Is(err, boom) {
		t.Fatalf("short random read = %v", err)
	}
	if _, err := io.ReadAll(strings.NewReader("ok")); err != nil {
		t.Fatal(err)
	}
}
