// Package githubadapter provides a hardened GitHub implementation of the
// credbound.SSOProvider port. GitHub is not an OpenID Connect issuer — it
// speaks plain OAuth 2.0 and identity comes from its REST API — so the
// generic OIDC adapter (ssoadapter) cannot serve it; this package owns that
// protocol gap with the standard library only.
//
// # Responsibilities
//
// The adapter owns the protocol exchange only: the authorization redirect
// (with a random state, a PKCE S256 challenge, and allow_signup=false), the
// code exchange at GitHub's token endpoint (presenting the PKCE verifier),
// and the REST reads of GET /user and GET /user/emails. Credbound keeps everything else — the sealed
// continuation carrying the adapter's opaque session, ceremony TTL, identity
// linking, persistence, audit, and revocation.
//
// # Registration
//
// Register a provider by wiring it into credbound.Config.SSOProviders:
//
//	provider, err := githubadapter.New(githubadapter.Config{
//		ConfigurationID: "0198b463-51a2-7cde-8000-0123456789ab", // UUIDv7 chosen by the host
//		ClientID:        os.Getenv("GITHUB_CLIENT_ID"),
//		ClientSecret:    os.Getenv("GITHUB_CLIENT_SECRET"),
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
// The provider's kind is always credbound.SSOProviderGitHub.
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
// # Subject and email trust
//
// The credbound subject is the decimal form of GitHub's numeric account id —
// the only stable identifier GitHub offers. The login is never used: logins
// are renameable and can be re-registered by someone else, which would let a
// freed name inherit a victim's linked identity. The primary email from
// GET /user/emails is forwarded with GitHub's own verified flag; when the
// user:email scope was declined the adapter falls back to the public profile
// email as unverified. Credbound keys SSO identities on issuer and subject,
// never on email, so an absent or unverified address only limits convenience.
//
// # No step-up, AAL1 only
//
// GitHub's authorization endpoint has no prompt=login or max_age equivalent:
// an authorization silently reuses whatever browser session GitHub already
// holds, and nothing in the response proves a fresh login. Begin therefore
// fails with ErrStepUpUnsupported when SSORequest.ForceReauthentication is
// set — a step-up ceremony must not pretend a re-authentication happened.
// For the same reason the adapter asserts no ACR or AMR, so without an
// explicit credbound.Config.SSOAssurance opt-out (TrustUnverified) a GitHub
// sign-in grants only AAL1. That is the correct posture: the adapter cannot
// verify that GitHub enforced a second factor. Hosts with hard step-up or
// MFA-assurance requirements should pair GitHub sign-in with a credbound
// second factor, or prefer an OIDC provider (ssoadapter) for those flows.
package githubadapter
