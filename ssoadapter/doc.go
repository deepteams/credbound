// Package ssoadapter provides a hardened, generic OpenID Connect
// implementation of the credbound.SSOProvider port, so hosts do not have to
// hand-roll the network side of SSO. Any spec-compliant OIDC issuer works
// through the generic adapter; Google and Microsoft Entra ID are plain OIDC
// issuers and need no dedicated code.
//
// # Responsibilities
//
// The adapter owns the protocol exchange only: discovery, the authorization
// code redirect (with PKCE S256, state, and nonce), the code exchange, and ID
// token verification. Credbound keeps everything else — the sealed
// continuation carrying the adapter's opaque session, ceremony TTL, identity
// linking, persistence, audit, and revocation.
//
// # Registration
//
// Register a provider by wiring it into credbound.Config.SSOProviders. Google
// through the generic adapter looks like this:
//
//	provider, err := ssoadapter.New(ssoadapter.Config{
//		ConfigurationID: "0198b463-51a2-7cde-8000-0123456789ab", // UUIDv7 chosen by the host
//		Kind:            credbound.SSOProviderGoogle,
//		IssuerURL:       "https://accounts.google.com",
//		ClientID:        os.Getenv("GOOGLE_CLIENT_ID"),
//		ClientSecret:    os.Getenv("GOOGLE_CLIENT_SECRET"),
//		RedirectURL:     "https://app.example.com/sso/callback",
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
// For Microsoft Entra ID use the tenant-specific issuer
// (https://login.microsoftonline.com/{tenant-id}/v2.0) with
// credbound.SSOProviderMicrosoft. The multi-tenant "common" endpoint is not
// supported because its issuer varies per tenant, which defeats strict issuer
// validation.
//
// # Callback handling
//
// The host's HTTP callback handler forwards the provider response verbatim to
// credbound's FinishSSO. The adapter accepts the full callback URL, the bare
// query string, or a JSON object with "code" and "state" fields:
//
//	func callback(w http.ResponseWriter, r *http.Request) {
//		continuation := readContinuationCookie(r)
//		auth, err := manager.FinishSSO(r.Context(), continuation, []byte(r.URL.String()))
//		// ...
//	}
//
// # Email trust
//
// The adapter forwards the email claim only when the issuer asserts
// email_verified=true. An unverified email is attacker-controlled input at
// many IdPs (anyone can type an address into a profile), so surfacing it
// would let a hostile account impersonate a victim's address in credbound's
// identity records. Issuers that never send email_verified (Microsoft Entra
// ID among them) therefore produce identities without an email; linking and
// login still work because credbound keys SSO identities on issuer and
// subject, never on email.
package ssoadapter
