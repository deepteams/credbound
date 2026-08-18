// Package samladapter provides a hardened SAML 2.0 service-provider
// implementation of the credbound.SSOProvider port, so hosts never hand-roll
// XML signature validation — historically the most dangerous part of SAML.
// The protocol exchange and XML-DSig verification are delegated to
// github.com/crewjam/saml; the adapter wraps them in credbound's ceremony
// contract and tightens the defaults.
//
// # Responsibilities
//
// The adapter owns the protocol exchange only: building the AuthnRequest for
// the IdP's HTTP-Redirect binding (signed when an SP key is configured) and
// validating the posted response against the IdP metadata — signature,
// issuer, audience, destination, recipient, validity window, InResponseTo,
// and exactly one assertion. Credbound keeps everything else: the sealed
// continuation carrying the adapter's opaque session, ceremony TTL, identity
// linking, persistence, audit, and revocation.
//
// # Registration
//
// Register a provider by wiring it into credbound.Config.SSOProviders.
// Static metadata is the primary path — paste the IdP's metadata document
// into the deployment so no network fetch ever happens:
//
//	metadataXML, err := os.ReadFile("idp-metadata.xml")
//	if err != nil {
//		log.Fatal(err)
//	}
//	provider, err := samladapter.New(samladapter.Config{
//		ConfigurationID: "0198b463-51a2-7cde-8000-0123456789ab", // UUIDv7 chosen by the host
//		MetadataXML:     metadataXML,
//		SPEntityID:      "https://app.example.com/saml/metadata",
//		ACSURL:          "https://app.example.com/saml/acs",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	manager, err := credbound.New(credbound.Config{
//		Store:        store,
//		Passwords:    hasher,
//		SecretKey:    secretKey,
//		SSOProviders: []credbound.SSOProvider{provider},
//	})
//
// MetadataURL exists for IdPs that rotate signing certificates too often to
// redeploy: it is fetched lazily over HTTPS with a 10-second timeout, cached,
// and re-fetched once the metadata TTL elapses (Config.MetadataRefreshInterval,
// 12 hours by default), so a
// rotated or revoked IdP signing certificate is picked up without a redeploy;
// a failed refresh keeps serving the last good document.
//
// # Callback handling
//
// The host's ACS endpoint (the HTTP-POST handler at ACSURL) forwards the
// provider response verbatim to credbound's FinishSSO. The adapter accepts
// either the raw base64 SAMLResponse form value or the full
// application/x-www-form-urlencoded request body:
//
//	func acs(w http.ResponseWriter, r *http.Request) {
//		continuation := readContinuationCookie(r)
//		body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
//		auth, err := manager.FinishSSO(r.Context(), continuation, body)
//		// ...
//	}
//
// # Subject and NameID policy
//
// The NameID becomes the credbound subject — half of the stable link key —
// so it must be durable. The adapter requests the persistent format and
// accepts persistent or unspecified NameIDs; a transient NameID changes per
// ceremony and is rejected unless Config.AllowTransientNameID is set for
// IdPs that mislabel stable identifiers. Email is read from the standard
// attributes (mail, email, urn:oid:0.9.2342.19200300.100.1.3, and the WS-Fed
// emailaddress claim URI) and forwarded as verified when it parses as a
// valid address: unlike an OIDC profile email, a SAML attribute is asserted
// by the IdP itself under the same signature as the subject. A malformed or
// oversized value is dropped, never fatal — credbound keys SSO identities on
// issuer and subject, never on email.
//
// # Step-up limitation
//
// credbound's step-up ceremonies set SSORequest.ForceReauthentication, which
// the adapter maps to ForceAuthn="true" on the AuthnRequest. SAML has no
// auth_time equivalent that the service provider can verify as strictly as
// OIDC's, so honoring ForceAuthn depends on the identity provider: the
// adapter cannot prove the IdP actually re-ran its authentication policy.
// Hosts with hard step-up requirements should prefer an OIDC provider
// (ssoadapter) for step-up flows.
package samladapter
