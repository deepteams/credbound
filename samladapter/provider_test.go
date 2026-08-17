package samladapter

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/deepteams/credbound"
)

func testConfig(idp *testIdP) Config {
	return Config{
		ConfigurationID: testConfigurationID,
		MetadataXML:     idp.metadataXML,
		SPEntityID:      testSPEntityID,
		ACSURL:          testACSURL,
	}
}

func newTestProvider(t *testing.T, idp *testIdP, mutate func(*Config)) *Provider {
	t.Helper()
	config := testConfig(idp)
	if mutate != nil {
		mutate(&config)
	}
	provider, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return provider
}

// begin runs Begin and returns the challenge plus the decoded session.
func begin(t *testing.T, provider *Provider, force bool) (credbound.SSOProviderChallenge, session) {
	t.Helper()
	challenge, err := provider.Begin(context.Background(), credbound.SSORequest{ForceReauthentication: force})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	var s session
	if err := json.Unmarshal(challenge.Session, &s); err != nil {
		t.Fatalf("session must be JSON: %v", err)
	}
	return challenge, s
}

func TestBeginBuildsRedirectAuthnRequest(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, s := begin(t, provider, false)

	if !strings.HasPrefix(challenge.RedirectURL, "https://idp.example.com/sso?") {
		t.Fatalf("redirect url = %q, want the IdP redirect SSO endpoint", challenge.RedirectURL)
	}
	requestXML := decodeAuthnRequest(t, challenge.RedirectURL)
	var request saml.AuthnRequest
	if err := xml.Unmarshal([]byte(requestXML), &request); err != nil {
		t.Fatalf("decode authn request: %v", err)
	}
	if request.ID == "" || request.ID != s.RequestID {
		t.Fatalf("session request id %q must match the AuthnRequest ID %q", s.RequestID, request.ID)
	}
	if request.Issuer == nil || request.Issuer.Value != testSPEntityID {
		t.Fatalf("issuer = %+v, want the SP entity id", request.Issuer)
	}
	if request.AssertionConsumerServiceURL != testACSURL {
		t.Fatalf("acs url = %q", request.AssertionConsumerServiceURL)
	}
	if request.ForceAuthn != nil {
		t.Fatal("ForceAuthn must be absent without forced re-authentication")
	}
	if request.NameIDPolicy == nil || request.NameIDPolicy.Format == nil || *request.NameIDPolicy.Format != string(saml.PersistentNameIDFormat) {
		t.Fatalf("NameIDPolicy = %+v, want the persistent format", request.NameIDPolicy)
	}
	if s.RelayState != "" {
		t.Fatal("Begin must not set a relay state")
	}

	// Two ceremonies never share a request id.
	_, second := begin(t, provider, false)
	if second.RequestID == s.RequestID {
		t.Fatal("request ids must be fresh per ceremony")
	}
}

func TestBeginForceReauthentication(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, true)

	requestXML := decodeAuthnRequest(t, challenge.RedirectURL)
	if !strings.Contains(requestXML, `ForceAuthn="true"`) {
		t.Fatalf("forced re-authentication must set ForceAuthn, got %s", requestXML)
	}
}

func TestBeginSignsRedirectWithSPKey(t *testing.T) {
	idp := newTestIdP(t)
	key, certificate := testKeyCert()
	provider := newTestProvider(t, idp, func(c *Config) {
		c.Key = key
		c.Certificate = certificate
	})
	challenge, _ := begin(t, provider, false)

	parsed, err := url.Parse(challenge.RedirectURL)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	query := parsed.Query()
	if query.Get("SigAlg") == "" || query.Get("Signature") == "" {
		t.Fatalf("signed redirect must carry SigAlg and Signature, got %v", query)
	}
}

func TestFinishHappyPath(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	s := defaultSession()
	s.UserEmail = "user@example.com"
	response := idp.respond(challenge.RedirectURL, s, nil)

	claims, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Issuer != idp.entityID() {
		t.Fatalf("issuer = %q, want the IdP entity id %q", claims.Issuer, idp.entityID())
	}
	if claims.Subject != "user-123" {
		t.Fatalf("subject = %q, want the NameID", claims.Subject)
	}
	if claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Fatalf("email must be forwarded as verified, got %+v", claims)
	}
}

func TestFinishAcceptsFormEncodedBody(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)

	body := "SAMLResponse=" + url.QueryEscape(response) + "&RelayState=anything"
	claims, err := provider.Finish(context.Background(), challenge.Session, []byte(body))
	if err != nil {
		t.Fatalf("Finish with form body: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestFinishRejectsWrongInResponseTo(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	first, _ := begin(t, provider, false)
	second, _ := begin(t, provider, false)
	// The response answers the second ceremony but is presented against the
	// first ceremony's session — an unsolicited response for that session.
	response := idp.respond(second.RedirectURL, defaultSession(), nil)

	_, err := provider.Finish(context.Background(), first.Session, []byte(response))
	if !errors.Is(err, ErrRequestIDMismatch) {
		t.Fatalf("err = %v, want ErrRequestIDMismatch", err)
	}
}

func TestFinishRejectsExpiredAssertion(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	past := time.Now().Add(-time.Hour)
	response := idp.respond(challenge.RedirectURL, defaultSession(), func(request *saml.IdpAuthnRequest) {
		request.Assertion.Conditions.NotBefore = past.Add(-time.Minute)
		request.Assertion.Conditions.NotOnOrAfter = past
		request.Assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = past
	})

	_, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expiry rejection", err)
	}
}

func TestFinishRejectsTamperedResponse(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)

	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	tampered := strings.Replace(string(decoded), "user-123", "user-999", 1)
	if tampered == string(decoded) {
		t.Fatal("tampering must change the response")
	}
	forged := base64.StdEncoding.EncodeToString([]byte(tampered))

	_, err = provider.Finish(context.Background(), challenge.Session, []byte(forged))
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("err = %v, want signature rejection", err)
	}
	if strings.Contains(err.Error(), "<saml") || strings.Contains(err.Error(), "<samlp") {
		t.Fatalf("error must not leak response XML: %v", err)
	}
}

func TestFinishRejectsWrongAudience(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)

	for name, audiences := range map[string][]saml.AudienceRestriction{
		"foreign audience": {{Audience: saml.Audience{Value: "https://other.example.com/saml/metadata"}}},
		// crewjam's default accepts an assertion without any
		// AudienceRestriction; the adapter's override must not.
		"no audience restriction": nil,
	} {
		t.Run(name, func(t *testing.T) {
			challenge, _ := begin(t, provider, false)
			response := idp.respond(challenge.RedirectURL, defaultSession(), func(request *saml.IdpAuthnRequest) {
				request.Assertion.Conditions.AudienceRestrictions = audiences
			})
			_, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
			if err == nil || !strings.Contains(err.Error(), "udience") {
				t.Fatalf("err = %v, want audience rejection", err)
			}
		})
	}
}

func TestFinishNameIDFormatPolicy(t *testing.T) {
	idp := newTestIdP(t)

	respondWithFormat := func(t *testing.T, provider *Provider, format string) (credbound.SSOClaims, error) {
		challenge, _ := begin(t, provider, false)
		s := defaultSession()
		s.NameIDFormat = format
		response := idp.respond(challenge.RedirectURL, s, nil)
		return provider.Finish(context.Background(), challenge.Session, []byte(response))
	}

	strict := newTestProvider(t, idp, nil)
	// The test IdP's default for an empty session format is transient.
	if _, err := respondWithFormat(t, strict, ""); !errors.Is(err, ErrTransientNameID) {
		t.Fatalf("err = %v, want ErrTransientNameID", err)
	}
	if _, err := respondWithFormat(t, strict, string(saml.UnspecifiedNameIDFormat)); err != nil {
		t.Fatalf("unspecified format must be accepted: %v", err)
	}
	if _, err := respondWithFormat(t, strict, string(saml.EmailAddressNameIDFormat)); err == nil || !strings.Contains(err.Error(), "unsupported NameID format") {
		t.Fatalf("err = %v, want unsupported-format rejection", err)
	}

	permissive := newTestProvider(t, idp, func(c *Config) { c.AllowTransientNameID = true })
	claims, err := respondWithFormat(t, permissive, string(saml.TransientNameIDFormat))
	if err != nil {
		t.Fatalf("AllowTransientNameID must accept a transient NameID: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Fatalf("claims = %+v", claims)
	}
}

func TestFinishEmailExtraction(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)

	finish := func(t *testing.T, mutate func(*saml.Session)) credbound.SSOClaims {
		t.Helper()
		challenge, _ := begin(t, provider, false)
		s := defaultSession()
		if mutate != nil {
			mutate(&s)
		}
		response := idp.respond(challenge.RedirectURL, s, nil)
		claims, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
		if err != nil {
			t.Fatalf("Finish: %v", err)
		}
		return claims
	}

	t.Run("mail oid attribute", func(t *testing.T) {
		claims := finish(t, func(s *saml.Session) { s.UserEmail = "oid@example.com" })
		if claims.Email != "oid@example.com" || !claims.EmailVerified {
			t.Fatalf("claims = %+v", claims)
		}
	})
	t.Run("ws-fed claim uri", func(t *testing.T) {
		claims := finish(t, func(s *saml.Session) {
			s.CustomAttributes = []saml.Attribute{{
				Name:   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
				Values: []saml.AttributeValue{{Type: "xs:string", Value: "wsfed@example.com"}},
			}}
		})
		if claims.Email != "wsfed@example.com" || !claims.EmailVerified {
			t.Fatalf("claims = %+v", claims)
		}
	})
	t.Run("friendly name", func(t *testing.T) {
		claims := finish(t, func(s *saml.Session) {
			s.CustomAttributes = []saml.Attribute{{
				FriendlyName: "Email",
				Name:         "urn:example:corp:email",
				Values:       []saml.AttributeValue{{Type: "xs:string", Value: "friendly@example.com"}},
			}}
		})
		if claims.Email != "friendly@example.com" {
			t.Fatalf("claims = %+v", claims)
		}
	})
	t.Run("invalid email dropped", func(t *testing.T) {
		claims := finish(t, func(s *saml.Session) { s.UserEmail = "not-an-email" })
		if claims.Email != "" || claims.EmailVerified {
			t.Fatalf("invalid email must be dropped, got %+v", claims)
		}
		if claims.Subject != "user-123" {
			t.Fatal("subject must survive a dropped email")
		}
	})
	t.Run("oversized email dropped", func(t *testing.T) {
		claims := finish(t, func(s *saml.Session) {
			s.UserEmail = strings.Repeat("a", maxEmailLength) + "@example.com"
		})
		if claims.Email != "" || claims.EmailVerified {
			t.Fatalf("oversized email must be dropped, got %+v", claims)
		}
	})
	t.Run("no email attribute", func(t *testing.T) {
		claims := finish(t, nil)
		if claims.Email != "" || claims.EmailVerified {
			t.Fatalf("claims = %+v", claims)
		}
	})
}

func TestFinishRejectsMultipleAssertions(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)

	decoded, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	text := string(decoded)
	start := strings.Index(text, "<saml:Assertion")
	end := strings.Index(text, "</saml:Assertion>") + len("</saml:Assertion>")
	if start < 0 || end <= start {
		t.Fatalf("cannot locate assertion in response")
	}
	doubled := text[:end] + text[start:end] + text[end:]
	forged := base64.StdEncoding.EncodeToString([]byte(doubled))

	_, err = provider.Finish(context.Background(), challenge.Session, []byte(forged))
	if err == nil || !strings.Contains(err.Error(), "exactly one assertion") {
		t.Fatalf("err = %v, want single-assertion rejection", err)
	}
}

func TestFinishRejectsMalformedInputs(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)

	cases := map[string]struct {
		session  []byte
		response []byte
	}{
		"garbage session":            {[]byte("not-json"), []byte(response)},
		"session without request id": {[]byte(`{"relay_state":"x"}`), []byte(response)},
		"empty response":             {challenge.Session, []byte("   ")},
		"bad base64":                 {challenge.Session, []byte("!!!not-base64!!!")},
		"garbage xml":                {challenge.Session, []byte(base64.StdEncoding.EncodeToString([]byte("not xml")))},
		"no assertion":               {challenge.Session, []byte(base64.StdEncoding.EncodeToString([]byte("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>")))},
		"form without SAMLResponse":  {challenge.Session, []byte("RelayState=only&SAMLResponse=")},
		"bad form encoding":          {challenge.Session, []byte("SAMLResponse=%zz")},
	}
	for name, tc := range cases {
		if _, err := provider.Finish(context.Background(), tc.session, tc.response); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestFinishValidatesRelayState(t *testing.T) {
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	sessionBytes := []byte(`{"request_id":"id-1234","relay_state":"expected"}`)

	// A session carrying a relay state requires the form body to echo it.
	if _, err := provider.Finish(context.Background(), sessionBytes, []byte("SAMLResponse=AAAA&RelayState=wrong")); err == nil || !strings.Contains(err.Error(), "RelayState") {
		t.Fatalf("err = %v, want relay state rejection", err)
	}
	if _, err := provider.Finish(context.Background(), sessionBytes, []byte("AAAA")); err == nil || !strings.Contains(err.Error(), "RelayState") {
		t.Fatalf("err = %v, want relay state rejection for a bare response", err)
	}
}

func TestFinishHonorsConfiguredClock(t *testing.T) {
	idp := newTestIdP(t)
	// crewjam validates with its package clock (real time), which passes for
	// a fresh response; the adapter's own re-check with the configured clock
	// must still reject a window that clock says has passed.
	provider := newTestProvider(t, idp, func(c *Config) {
		c.Clock = func() time.Time { return time.Now().Add(48 * time.Hour) }
	})
	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)

	_, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expiry from the configured clock", err)
	}
}

func TestCheckConditions(t *testing.T) {
	now := time.Now()
	provider := &Provider{now: func() time.Time { return now }}

	if err := provider.checkConditions(nil); err == nil {
		t.Fatal("missing conditions must be rejected")
	}
	if err := provider.checkConditions(&saml.Conditions{NotBefore: now.Add(time.Hour)}); err == nil {
		t.Fatal("a future NotBefore must be rejected")
	}
	if err := provider.checkConditions(&saml.Conditions{NotOnOrAfter: now.Add(-time.Hour)}); err == nil {
		t.Fatal("a past NotOnOrAfter must be rejected")
	}
	within := &saml.Conditions{NotBefore: now.Add(time.Minute), NotOnOrAfter: now.Add(-time.Minute)}
	if err := provider.checkConditions(within); err != nil {
		t.Fatalf("clock skew leeway must be granted: %v", err)
	}
}

func TestMetadataURLFetchedLazilyOnceAndRetried(t *testing.T) {
	idp := newTestIdP(t)
	var fetches, status atomic.Int64
	status.Store(http.StatusInternalServerError)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if code := int(status.Load()); code != http.StatusOK {
			w.WriteHeader(code)
			return
		}
		_, _ = w.Write(idp.metadataXML)
	}))
	t.Cleanup(server.Close)

	provider := newTestProvider(t, idp, func(c *Config) {
		c.MetadataXML = nil
		c.MetadataURL = server.URL
	})
	if fetches.Load() != 0 {
		t.Fatal("metadata must not be fetched at construction")
	}

	// A failed fetch surfaces and is retried on the next ceremony.
	if _, err := provider.Begin(context.Background(), credbound.SSORequest{}); err == nil || !strings.Contains(err.Error(), "fetch idp metadata") {
		t.Fatalf("err = %v, want metadata fetch failure", err)
	}
	status.Store(http.StatusOK)
	if _, err := provider.Begin(context.Background(), credbound.SSORequest{}); err != nil {
		t.Fatalf("Begin after recovery: %v", err)
	}

	// A successful fetch is cached for the provider's lifetime.
	before := fetches.Load()
	if _, err := provider.Begin(context.Background(), credbound.SSORequest{}); err != nil {
		t.Fatalf("Begin from cache: %v", err)
	}
	if fetches.Load() != before {
		t.Fatalf("metadata must be fetched once, got %d fetches", fetches.Load())
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	idp := newTestIdP(t)
	key, certificate := testKeyCert()
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	noRedirectMetadata := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`)
	anonymousMetadata := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/></IDPSSODescriptor></EntityDescriptor>`)

	cases := map[string]func(*Config){
		"bad uuid":              func(c *Config) { c.ConfigurationID = "not-a-uuid" },
		"uuid v4":               func(c *Config) { c.ConfigurationID = "0198b463-0000-4000-8000-0000000000aa" },
		"no metadata":           func(c *Config) { c.MetadataXML = nil },
		"both metadata sources": func(c *Config) { c.MetadataURL = "https://idp.example.com/metadata" },
		"garbage metadata":      func(c *Config) { c.MetadataXML = []byte("not xml") },
		"metadata without redirect sso": func(c *Config) {
			c.MetadataXML = noRedirectMetadata
		},
		"metadata without entity id": func(c *Config) {
			c.MetadataXML = anonymousMetadata
		},
		"http metadata url": func(c *Config) {
			c.MetadataXML = nil
			c.MetadataURL = "http://idp.example.com/metadata"
		},
		"missing sp entity id": func(c *Config) { c.SPEntityID = "  " },
		"missing acs":          func(c *Config) { c.ACSURL = "" },
		"http acs":             func(c *Config) { c.ACSURL = "http://app.example.com/saml/acs" },
		"bad acs scheme":       func(c *Config) { c.ACSURL = "ftp://app.example.com/saml/acs" },
		"key without cert":     func(c *Config) { c.Key = key },
		"cert without key":     func(c *Config) { c.Certificate = certificate },
		"unsupported key type": func(c *Config) {
			c.Key = ed25519Key
			c.Certificate = certificate
		},
	}
	for name, mutate := range cases {
		config := testConfig(idp)
		mutate(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("%s: expected configuration error", name)
		}
	}
}

func TestNewAcceptsEntitiesDescriptorMetadata(t *testing.T) {
	idp := newTestIdP(t)
	wrapped := []byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + string(idp.metadataXML) + `</EntitiesDescriptor>`)
	provider := newTestProvider(t, idp, func(c *Config) { c.MetadataXML = wrapped })

	challenge, _ := begin(t, provider, false)
	response := idp.respond(challenge.RedirectURL, defaultSession(), nil)
	claims, err := provider.Finish(context.Background(), challenge.Session, []byte(response))
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if claims.Issuer != idp.entityID() {
		t.Fatalf("issuer = %q", claims.Issuer)
	}
}

func TestNewDefaultsAndOverrides(t *testing.T) {
	idp := newTestIdP(t)

	provider := newTestProvider(t, idp, nil)
	if provider.Kind() != credbound.SSOProviderSAML {
		t.Fatalf("kind = %q, want saml", provider.Kind())
	}
	if provider.ConfigurationID() != testConfigurationID {
		t.Fatalf("configuration id = %q", provider.ConfigurationID())
	}
	if provider.client.Timeout != defaultTimeout {
		t.Fatalf("default client timeout = %v", provider.client.Timeout)
	}

	custom := &http.Client{}
	provider = newTestProvider(t, idp, func(c *Config) { c.HTTPClient = custom })
	if provider.client == custom || provider.client.Timeout != defaultTimeout {
		t.Fatal("a caller client without a timeout must be copied and given the default timeout")
	}
	if custom.Timeout != 0 {
		t.Fatal("the caller's client must not be mutated")
	}

	timed := &http.Client{Timeout: time.Minute}
	provider = newTestProvider(t, idp, func(c *Config) { c.HTTPClient = timed })
	if provider.client != timed {
		t.Fatal("a caller client with a timeout must be used as-is")
	}
}

// TestProviderSatisfiesPortRegistration proves the registration contract
// (UUIDv7 + the SAML kind) that credbound.New enforces holds by construction.
func TestProviderSatisfiesPortRegistration(t *testing.T) {
	var _ credbound.SSOProvider = (*Provider)(nil)
	idp := newTestIdP(t)
	provider := newTestProvider(t, idp, nil)
	if !validUUIDv7(provider.ConfigurationID()) {
		t.Fatal("configuration id must satisfy credbound's UUIDv7 registration rule")
	}
	if provider.Kind() != credbound.SSOProviderSAML {
		t.Fatal("kind must be the SAML provider kind")
	}
}
