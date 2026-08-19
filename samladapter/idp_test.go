package samladapter

import (
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"github.com/deepteams/credbound"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

var (
	testConfigurationID = credbound.MustParseUUID("0198b463-51a2-7cde-8000-0123456789ab")
	testSPEntityID      = "https://app.example.com/saml/metadata"
	testACSURL          = "https://app.example.com/saml/acs"
)

// testKeyCert is generated once per test binary: RSA key generation is the
// slowest part of the suite and every test IdP can share the same throwaway
// identity.
var testKeyCert = sync.OnceValues(func() (*rsa.PrivateKey, *x509.Certificate) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "samladapter-test-idp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return key, certificate
})

// spDirectory serves the registered SP metadata to the test IdP.
type spDirectory struct{ metadata *saml.EntityDescriptor }

func (d spDirectory) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if id == d.metadata.EntityID {
		return d.metadata, nil
	}
	return nil, os.ErrNotExist
}

// testIdP is an in-process identity provider built from crewjam/saml's own
// IdentityProvider type, so responses are signed with the library's real
// XML-DSig implementation.
type testIdP struct {
	t           *testing.T
	idp         *saml.IdentityProvider
	metadataXML []byte
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, certificate := testKeyCert()
	acsURL, err := url.Parse(testACSURL)
	if err != nil {
		t.Fatalf("parse acs url: %v", err)
	}
	spMetadata := (&saml.ServiceProvider{EntityID: testSPEntityID, AcsURL: *acsURL}).Metadata()
	idp := &saml.IdentityProvider{
		Key:                     key,
		Certificate:             certificate,
		MetadataURL:             url.URL{Scheme: "https", Host: "idp.example.com", Path: "/metadata"},
		SSOURL:                  url.URL{Scheme: "https", Host: "idp.example.com", Path: "/sso"},
		ServiceProviderProvider: spDirectory{metadata: spMetadata},
	}
	metadataXML, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatalf("marshal idp metadata: %v", err)
	}
	return &testIdP{t: t, idp: idp, metadataXML: metadataXML}
}

// entityID is the issuer the adapter must report in SSOClaims.
func (i *testIdP) entityID() string { return i.idp.MetadataURL.String() }

// defaultSession is a login with a persistent NameID, the shape a
// well-configured IdP produces.
func defaultSession() saml.Session {
	return saml.Session{
		ID:           "session-1",
		CreateTime:   time.Now(),
		NameID:       "user-123",
		NameIDFormat: string(saml.PersistentNameIDFormat),
	}
}

// respond consumes the SAMLRequest from a Begin redirect URL and returns the
// base64 SAMLResponse an IdP would post to the ACS endpoint. mutate, when
// set, edits the assertion before it is signed.
func (i *testIdP) respond(redirectURL string, s saml.Session, mutate func(*saml.IdpAuthnRequest)) string {
	i.t.Helper()
	request, err := saml.NewIdpAuthnRequest(i.idp, httptest.NewRequest(http.MethodGet, redirectURL, nil))
	if err != nil {
		i.t.Fatalf("read authn request: %v", err)
	}
	if err := request.Validate(); err != nil {
		i.t.Fatalf("validate authn request: %v", err)
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(request, &s); err != nil {
		i.t.Fatalf("make assertion: %v", err)
	}
	if mutate != nil {
		mutate(request)
	}
	if err := request.MakeAssertionEl(); err != nil {
		i.t.Fatalf("sign assertion: %v", err)
	}
	form, err := request.PostBinding()
	if err != nil {
		i.t.Fatalf("make response: %v", err)
	}
	return form.SAMLResponse
}

// decodeAuthnRequest inflates the SAMLRequest query parameter of a Begin
// redirect URL back into XML.
func decodeAuthnRequest(t *testing.T, redirectURL string) string {
	t.Helper()
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect url: %v", err)
	}
	compressed, err := base64.StdEncoding.DecodeString(parsed.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode SAMLRequest: %v", err)
	}
	inflated, err := io.ReadAll(flate.NewReader(strings.NewReader(string(compressed))))
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	return string(inflated)
}
