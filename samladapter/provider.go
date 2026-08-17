package samladapter

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/crewjam/saml"
	"github.com/deepteams/credbound"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	// defaultTimeout bounds the one-shot metadata fetch when the host does
	// not supply an HTTP client, and is applied to supplied clients that
	// carry no timeout of their own so a stalled IdP cannot hold Begin open.
	defaultTimeout = 10 * time.Second
	// maxClaimLength mirrors the issuer and subject cap enforced by
	// credbound in sso.go; the adapter fails fast with a descriptive error
	// instead of letting the library collapse it into ErrInvalidCredentials.
	maxClaimLength = 500
	// maxEmailLength mirrors credbound's email validation cap. An oversized
	// email attribute is dropped rather than failing the ceremony, because
	// SSO identities are keyed on issuer and subject, never on email.
	maxEmailLength = 320
	// clockSkew is the leeway the adapter grants when it re-validates the
	// assertion's NotBefore and NotOnOrAfter conditions with the configured
	// clock. It mirrors crewjam/saml's saml.MaxClockSkew default.
	clockSkew = 3 * time.Minute
	// maxMetadataSize caps how much IdP metadata the lazy URL fetch reads.
	maxMetadataSize = 5 << 20
	// maxFormatEcho caps how much of an IdP-controlled NameID format URI is
	// echoed into adapter errors.
	maxFormatEcho = 100
)

// Sentinel errors for the verification failures hosts most often want to
// distinguish in logs. Credbound maps every Finish error to
// ErrInvalidCredentials before it reaches the end user.
var (
	// ErrRequestIDMismatch reports that the response's InResponseTo does not
	// match the request id issued in Begin — an unsolicited or replayed
	// response.
	ErrRequestIDMismatch = errors.New("samladapter: InResponseTo does not match the ceremony request id")
	// ErrTransientNameID reports that the IdP asserted a transient NameID,
	// which cannot serve as a stable link key. Set
	// Config.AllowTransientNameID to accept it anyway.
	ErrTransientNameID = errors.New("samladapter: transient NameID rejected; set AllowTransientNameID to accept it")
)

// emailAttributeNames are the assertion attribute names (compared
// case-insensitively) the adapter reads the email claim from, in the forms
// the common IdPs emit: LDAP-ish short names, the mail OID, and the WS-Fed
// claim URI used by ADFS and Entra ID.
var emailAttributeNames = map[string]bool{
	"mail":                              true,
	"email":                             true,
	"urn:oid:0.9.2342.19200300.100.1.3": true,
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": true,
}

// Config describes one SAML identity provider registration.
type Config struct {
	// ConfigurationID is the host-chosen UUIDv7 under which credbound
	// indexes this provider and its linked identities. Required.
	ConfigurationID string
	// MetadataXML is the IdP metadata document (an EntityDescriptor, or an
	// EntitiesDescriptor containing one IdP role). Static metadata is the
	// primary, recommended path: it is parsed eagerly so misconfiguration
	// surfaces at construction, and it never makes the adapter reach out to
	// the network. Exactly one of MetadataXML and MetadataURL must be set.
	MetadataXML []byte
	// MetadataURL is fetched lazily, once, on first use, with a 10-second
	// timeout and the same SSRF posture as the rest of the adapter: HTTPS
	// only, except for loopback hosts which may use HTTP in development.
	// A failed fetch is retried on the next ceremony. Prefer MetadataXML;
	// use MetadataURL only when the IdP rotates certificates too often to
	// redeploy with fresh static metadata.
	MetadataURL string
	// SPEntityID is this service provider's entity ID: the value the IdP
	// must put in the assertion's AudienceRestriction and the Issuer of the
	// AuthnRequests the adapter emits. Required.
	SPEntityID string
	// ACSURL is the host's assertion consumer service URL — the endpoint
	// whose handler forwards the posted response to credbound's FinishSSO.
	// The assertion's Destination and SubjectConfirmation Recipient must
	// match it. Required. HTTPS is mandatory except for loopback hosts.
	ACSURL string
	// Certificate is the SP signing certificate, paired with Key. Optional;
	// when both are set, HTTP-Redirect AuthnRequests are signed (SigAlg and
	// Signature query parameters, SHA-256). Set both or neither.
	Certificate *x509.Certificate
	// Key is the SP signing key: an *rsa.PrivateKey or *ecdsa.PrivateKey.
	Key crypto.Signer
	// AllowTransientNameID accepts transient-format NameIDs as the subject.
	// Off by default because a transient NameID changes per ceremony and
	// therefore cannot key a durable credbound SSO identity; enable it only
	// for IdPs that mislabel stable identifiers as transient.
	AllowTransientNameID bool
	// HTTPClient is used only for the one-shot MetadataURL fetch. Defaults
	// to a client with a 10-second timeout; a supplied client without a
	// timeout is shallow-copied and given the default.
	HTTPClient *http.Client
	// Clock supplies the current time for the adapter's own re-validation of
	// assertion conditions. Defaults to time.Now. Note that crewjam/saml
	// validates its timestamps with its package-level saml.TimeNow, which
	// this per-provider clock does not replace.
	Clock func() time.Time
}

// Provider is a SAML 2.0 service-provider implementation of
// credbound.SSOProvider backed by github.com/crewjam/saml for the protocol
// and XML-DSig validation. It is stateless across ceremonies: everything a
// Finish needs travels inside the opaque Session bytes that credbound seals
// into its continuation.
type Provider struct {
	configurationID string
	spEntityID      string
	acsURL          url.URL
	key             crypto.Signer
	certificate     *x509.Certificate
	signatureMethod string
	allowTransient  bool
	metadataURL     string
	client          *http.Client
	now             func() time.Time

	mu       sync.Mutex
	metadata *saml.EntityDescriptor
}

// session is the opaque payload carried through credbound's sealed
// continuation between Begin and Finish. It never reaches the browser in
// clear text: credbound encrypts it with its AEAD seal.
type session struct {
	RequestID  string `json:"request_id"`
	RelayState string `json:"relay_state,omitempty"`
}

// New validates the configuration and returns a Provider ready to register
// in credbound.Config.SSOProviders. Static metadata is parsed eagerly;
// MetadataURL is fetched lazily on first use so construction does not
// require the IdP to be reachable.
func New(config Config) (*Provider, error) {
	if !validUUIDv7(config.ConfigurationID) {
		return nil, errors.New("samladapter: configuration id must be a UUIDv7")
	}
	spEntityID := strings.TrimSpace(config.SPEntityID)
	if spEntityID == "" {
		return nil, errors.New("samladapter: sp entity id is required")
	}
	acsRaw := strings.TrimSpace(config.ACSURL)
	if err := validEndpointURL(acsRaw); err != nil {
		return nil, fmt.Errorf("samladapter: acs url: %w", err)
	}
	acsURL, err := url.Parse(acsRaw)
	if err != nil {
		return nil, fmt.Errorf("samladapter: acs url: %w", err)
	}
	if (config.Key == nil) != (config.Certificate == nil) {
		return nil, errors.New("samladapter: sp key and certificate must be set together")
	}
	signatureMethod := ""
	switch config.Key.(type) {
	case nil:
	case *rsa.PrivateKey:
		signatureMethod = dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		signatureMethod = dsig.ECDSASHA256SignatureMethod
	default:
		return nil, errors.New("samladapter: sp key must be an *rsa.PrivateKey or *ecdsa.PrivateKey")
	}
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	provider := &Provider{
		configurationID: config.ConfigurationID,
		spEntityID:      spEntityID,
		acsURL:          *acsURL,
		key:             config.Key,
		certificate:     config.Certificate,
		signatureMethod: signatureMethod,
		allowTransient:  config.AllowTransientNameID,
		client:          httpClient(config.HTTPClient),
		now:             clock,
	}
	hasXML, hasURL := len(config.MetadataXML) > 0, strings.TrimSpace(config.MetadataURL) != ""
	switch {
	case hasXML && hasURL:
		return nil, errors.New("samladapter: set exactly one of MetadataXML and MetadataURL, not both")
	case hasXML:
		metadata, err := parseMetadata(config.MetadataXML)
		if err != nil {
			return nil, err
		}
		provider.metadata = metadata
	case hasURL:
		metadataURL := strings.TrimSpace(config.MetadataURL)
		if err := validEndpointURL(metadataURL); err != nil {
			return nil, fmt.Errorf("samladapter: metadata url: %w", err)
		}
		provider.metadataURL = metadataURL
	default:
		return nil, errors.New("samladapter: idp metadata is required (set MetadataXML or MetadataURL)")
	}
	return provider, nil
}

// ConfigurationID implements credbound.SSOProvider.
func (p *Provider) ConfigurationID() string { return p.configurationID }

// Kind implements credbound.SSOProvider.
func (p *Provider) Kind() credbound.SSOProviderKind { return credbound.SSOProviderSAML }

// Begin implements credbound.SSOProvider. It builds an AuthnRequest for the
// IdP's HTTP-Redirect SSO endpoint (deflated, base64- and URL-encoded, and
// signed when an SP key is configured) and returns the request id as opaque
// Session bytes for credbound to seal into its continuation.
//
// When SSORequest.ForceReauthentication is set the request carries
// ForceAuthn="true". SAML gives the SP no auth_time-equivalent to verify
// afterwards, so unlike the OIDC adapter this remains a request the IdP is
// trusted — not proven — to honor; see the package documentation.
func (p *Provider) Begin(ctx context.Context, request credbound.SSORequest) (credbound.SSOProviderChallenge, error) {
	sp, err := p.serviceProvider(ctx, "")
	if err != nil {
		return credbound.SSOProviderChallenge{}, err
	}
	if request.ForceReauthentication {
		force := true
		sp.ForceAuthn = &force
	}
	location := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if location == "" {
		return credbound.SSOProviderChallenge{}, errors.New("samladapter: idp metadata advertises no HTTP-Redirect SSO endpoint")
	}
	authnRequest, err := sp.MakeAuthenticationRequest(location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return credbound.SSOProviderChallenge{}, fmt.Errorf("samladapter: build authentication request: %w", err)
	}
	redirect, err := authnRequest.Redirect("", sp)
	if err != nil {
		return credbound.SSOProviderChallenge{}, fmt.Errorf("samladapter: encode redirect: %w", err)
	}
	payload, err := json.Marshal(session{RequestID: authnRequest.ID})
	if err != nil {
		return credbound.SSOProviderChallenge{}, fmt.Errorf("samladapter: encode session: %w", err)
	}
	return credbound.SSOProviderChallenge{RedirectURL: redirect.String(), Session: payload}, nil
}

// Finish implements credbound.SSOProvider. sessionBytes is the Session
// issued by Begin (returned by credbound from its sealed continuation) and
// response is the payload the host's ACS handler received: either the raw
// base64 SAMLResponse form value or the full application/x-www-form-urlencoded
// request body — both are detected and handled.
//
// Finish validates the response through crewjam/saml against the IdP
// metadata: XML signature, issuer, destination and recipient (the ACS URL),
// NotBefore/NotOnOrAfter with a small clock skew, and audience, which the
// adapter tightens to require an AudienceRestriction naming SPEntityID. The
// response and every SubjectConfirmation must carry an InResponseTo equal
// (constant-time) to the Session's request id, so unsolicited and
// IdP-initiated responses are rejected, and the response must contain
// exactly one assertion. The verified claims map Issuer to the IdP entity
// ID and Subject to the NameID, whose format must be persistent or
// unspecified (transient only with AllowTransientNameID). Errors never
// include assertion or response XML.
func (p *Provider) Finish(ctx context.Context, sessionBytes, response []byte) (credbound.SSOClaims, error) {
	var state session
	if err := json.Unmarshal(sessionBytes, &state); err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("samladapter: decode session: %w", err)
	}
	if strings.TrimSpace(state.RequestID) == "" {
		return credbound.SSOClaims{}, errors.New("samladapter: session carries no request id")
	}
	encoded, relayState, isForm, err := extractResponse(response)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	if state.RelayState != "" {
		if !isForm || subtle.ConstantTimeCompare([]byte(relayState), []byte(state.RelayState)) != 1 {
			return credbound.SSOClaims{}, errors.New("samladapter: RelayState does not match the ceremony")
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(stripSpace(encoded))
	if err != nil {
		return credbound.SSOClaims{}, fmt.Errorf("samladapter: decode SAMLResponse base64: %w", err)
	}
	if err := requireSingleAssertion(decoded); err != nil {
		return credbound.SSOClaims{}, err
	}
	sp, err := p.serviceProvider(ctx, state.RequestID)
	if err != nil {
		return credbound.SSOClaims{}, err
	}
	assertion, err := sp.ParseXMLResponse(decoded, []string{state.RequestID}, sp.AcsURL)
	if err != nil {
		return credbound.SSOClaims{}, sanitizeResponseError(err)
	}
	return p.claims(assertion, state.RequestID)
}

// claims maps a crewjam-verified assertion onto credbound.SSOClaims and
// applies the adapter's own policy: NameID format, a constant-time
// InResponseTo re-check on every SubjectConfirmation, a condition re-check
// with the configured clock, credbound's length caps, and email extraction.
func (p *Provider) claims(assertion *saml.Assertion, requestID string) (credbound.SSOClaims, error) {
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return credbound.SSOClaims{}, errors.New("samladapter: assertion carries no subject NameID")
	}
	nameID := assertion.Subject.NameID
	switch nameID.Format {
	case "", string(saml.UnspecifiedNameIDFormat), string(saml.PersistentNameIDFormat):
	case string(saml.TransientNameIDFormat):
		if !p.allowTransient {
			return credbound.SSOClaims{}, ErrTransientNameID
		}
	default:
		return credbound.SSOClaims{}, fmt.Errorf("samladapter: unsupported NameID format %q", truncate(nameID.Format, maxFormatEcho))
	}
	if len(assertion.Subject.SubjectConfirmations) == 0 {
		return credbound.SSOClaims{}, errors.New("samladapter: assertion carries no SubjectConfirmation")
	}
	for _, confirmation := range assertion.Subject.SubjectConfirmations {
		data := confirmation.SubjectConfirmationData
		if data == nil || subtle.ConstantTimeCompare([]byte(data.InResponseTo), []byte(requestID)) != 1 {
			return credbound.SSOClaims{}, ErrRequestIDMismatch
		}
	}
	if err := p.checkConditions(assertion.Conditions); err != nil {
		return credbound.SSOClaims{}, err
	}
	issuer, subject := strings.TrimSpace(assertion.Issuer.Value), strings.TrimSpace(nameID.Value)
	if issuer == "" || subject == "" || len(issuer) > maxClaimLength || len(subject) > maxClaimLength {
		return credbound.SSOClaims{}, errors.New("samladapter: issuer or subject is empty or exceeds 500 characters")
	}
	claims := credbound.SSOClaims{Issuer: issuer, Subject: subject}
	// SAML attributes are asserted by the IdP itself (typically from its
	// directory) under the same signature as the subject, so a present,
	// well-formed email is forwarded as verified. A malformed or oversized
	// value is dropped rather than failing the ceremony, because credbound
	// keys SSO identities on issuer and subject, never on email.
	if email := emailAttribute(assertion); email != "" && len(email) <= maxEmailLength {
		if parsed, err := mail.ParseAddress(email); err == nil && parsed.Address == email {
			claims.Email, claims.EmailVerified = email, true
		}
	}
	return claims, nil
}

// checkConditions re-validates the assertion validity window with the
// configured clock. crewjam/saml already performs this check with its
// package-level saml.TimeNow; this pass makes Config.Clock authoritative.
func (p *Provider) checkConditions(conditions *saml.Conditions) error {
	if conditions == nil {
		return errors.New("samladapter: assertion carries no Conditions")
	}
	now := p.now()
	if !conditions.NotBefore.IsZero() && now.Add(clockSkew).Before(conditions.NotBefore) {
		return errors.New("samladapter: assertion is not yet valid")
	}
	if !conditions.NotOnOrAfter.IsZero() && !now.Before(conditions.NotOnOrAfter.Add(clockSkew)) {
		return errors.New("samladapter: assertion has expired")
	}
	return nil
}

// serviceProvider assembles the crewjam service provider for one call. A
// fresh value per ceremony keeps per-request settings (ForceAuthn, the
// request id validator) off the shared Provider. requestID is empty in
// Begin and set in Finish, where it pins InResponseTo with a constant-time
// comparison — crewjam's own possibleRequestIDs check compares with == — and
// where the audience check is tightened: crewjam accepts assertions without
// any AudienceRestriction, the adapter does not.
func (p *Provider) serviceProvider(ctx context.Context, requestID string) (*saml.ServiceProvider, error) {
	metadata, err := p.idpMetadata(ctx)
	if err != nil {
		return nil, err
	}
	nameIDFormat := saml.PersistentNameIDFormat
	if p.allowTransient {
		nameIDFormat = saml.UnspecifiedNameIDFormat
	}
	sp := &saml.ServiceProvider{
		EntityID:          p.spEntityID,
		AcsURL:            p.acsURL,
		IDPMetadata:       metadata,
		Key:               p.key,
		Certificate:       p.certificate,
		SignatureMethod:   p.signatureMethod,
		AuthnNameIDFormat: nameIDFormat,
	}
	if requestID != "" {
		sp.ValidateRequestID = func(response saml.Response, _ []string) error {
			if subtle.ConstantTimeCompare([]byte(response.InResponseTo), []byte(requestID)) != 1 {
				return ErrRequestIDMismatch
			}
			return nil
		}
		sp.ValidateAudienceRestriction = func(assertion *saml.Assertion) error {
			for _, restriction := range assertion.Conditions.AudienceRestrictions {
				if restriction.Audience.Value == p.spEntityID {
					return nil
				}
			}
			return fmt.Errorf("samladapter: no AudienceRestriction names %q", p.spEntityID)
		}
	}
	return sp, nil
}

// idpMetadata returns the cached IdP metadata, fetching MetadataURL once on
// first use. Failures are retried on the next call; success is cached for
// the provider's lifetime (metadata rotation means a new Provider).
func (p *Provider) idpMetadata(ctx context.Context) (*saml.EntityDescriptor, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metadata != nil {
		return p.metadata, nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("samladapter: fetch idp metadata: %w", err)
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("samladapter: fetch idp metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("samladapter: fetch idp metadata: unexpected status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataSize+1))
	if err != nil {
		return nil, fmt.Errorf("samladapter: fetch idp metadata: %w", err)
	}
	if len(body) > maxMetadataSize {
		return nil, errors.New("samladapter: idp metadata exceeds the size limit")
	}
	metadata, err := parseMetadata(body)
	if err != nil {
		return nil, err
	}
	p.metadata = metadata
	return metadata, nil
}

// parseMetadata decodes and validates an IdP metadata document: either an
// EntityDescriptor or an EntitiesDescriptor holding one entity with an IdP
// role. The XML is round-trip checked first so namespace-confusion tricks
// that survive encoding/xml are rejected.
func parseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("samladapter: idp metadata: %w", err)
	}
	entity := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(data, entity); err != nil {
		var entities saml.EntitiesDescriptor
		if err := xml.Unmarshal(data, &entities); err != nil {
			return nil, fmt.Errorf("samladapter: idp metadata: %w", err)
		}
		entity = nil
		for index, candidate := range entities.EntityDescriptors {
			if len(candidate.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[index]
				break
			}
		}
		if entity == nil {
			return nil, errors.New("samladapter: idp metadata: no entity with an IDPSSODescriptor")
		}
	}
	return validateMetadata(entity)
}

func validateMetadata(entity *saml.EntityDescriptor) (*saml.EntityDescriptor, error) {
	entityID := strings.TrimSpace(entity.EntityID)
	if entityID == "" || len(entityID) > maxClaimLength {
		return nil, errors.New("samladapter: idp metadata: entity id is empty or exceeds 500 characters")
	}
	for _, descriptor := range entity.IDPSSODescriptors {
		for _, service := range descriptor.SingleSignOnServices {
			if service.Binding == saml.HTTPRedirectBinding && service.Location != "" {
				return entity, nil
			}
		}
	}
	return nil, errors.New("samladapter: idp metadata: no HTTP-Redirect single sign-on endpoint")
}

// sanitizeResponseError converts crewjam's InvalidResponseError — whose
// struct carries the full response XML — into an error built from its
// diagnostic cause only, so assertion XML never reaches host logs.
func sanitizeResponseError(err error) error {
	var invalid *saml.InvalidResponseError
	if errors.As(err, &invalid) && invalid.PrivateErr != nil {
		return fmt.Errorf("samladapter: validate response: %w", invalid.PrivateErr)
	}
	return fmt.Errorf("samladapter: validate response: %w", err)
}

// requireSingleAssertion rejects responses whose top level carries anything
// but exactly one assertion. crewjam validates and returns the first valid
// assertion of potentially several; a multi-assertion response is out of
// contract for a login ceremony and fails closed here instead.
func requireSingleAssertion(decoded []byte) error {
	var shape struct {
		Assertions []struct{} `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
		Encrypted  []struct{} `xml:"urn:oasis:names:tc:SAML:2.0:assertion EncryptedAssertion"`
	}
	if err := xml.Unmarshal(decoded, &shape); err != nil {
		return fmt.Errorf("samladapter: parse response: %w", err)
	}
	if count := len(shape.Assertions) + len(shape.Encrypted); count != 1 {
		return fmt.Errorf("samladapter: response must carry exactly one assertion, got %d", count)
	}
	return nil
}

// extractResponse pulls the base64 SAMLResponse out of the host's raw
// payload: either the bare form value or the full
// application/x-www-form-urlencoded body posted to the ACS endpoint.
func extractResponse(response []byte) (encoded, relayState string, isForm bool, err error) {
	raw := strings.TrimSpace(string(response))
	if raw == "" {
		return "", "", false, errors.New("samladapter: empty response")
	}
	if !strings.Contains(raw, "SAMLResponse=") {
		return raw, "", false, nil
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", "", false, fmt.Errorf("samladapter: parse form body: %w", err)
	}
	encoded = values.Get("SAMLResponse")
	if encoded == "" {
		return "", "", false, errors.New("samladapter: form body carries no SAMLResponse")
	}
	return encoded, values.Get("RelayState"), true, nil
}

// emailAttribute returns the first non-empty value of a recognized email
// attribute, matching Name or FriendlyName case-insensitively.
func emailAttribute(assertion *saml.Assertion) string {
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if !emailAttributeNames[strings.ToLower(attribute.Name)] && !emailAttributeNames[strings.ToLower(attribute.FriendlyName)] {
				continue
			}
			for _, value := range attribute.Values {
				if email := strings.TrimSpace(value.Value); email != "" {
					return email
				}
			}
		}
	}
	return ""
}

func stripSpace(value string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, value)
}

func httpClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Timeout: defaultTimeout}
	}
	if client.Timeout == 0 {
		clone := *client
		clone.Timeout = defaultTimeout
		return &clone
	}
	return client
}

func validEndpointURL(value string) error {
	if value == "" {
		return errors.New("required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	host := parsed.Hostname()
	switch parsed.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return errors.New("http is only allowed for loopback hosts")
		}
	default:
		return fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if host == "" {
		return errors.New("missing host")
	}
	return nil
}

// validUUIDv7 mirrors credbound's registration rule so misconfiguration
// surfaces at adapter construction instead of at credbound.New.
func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '7' {
		return false
	}
	if !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
