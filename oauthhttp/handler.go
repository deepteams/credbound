package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/deepteams/credbound"
)

const maxProtocolBody = 64 << 10

// HandlerConfig wires a Handler to one issuer and to the host's session and
// consent machinery.
type HandlerConfig struct {
	// Issuer is the authorization server's canonical https:// URL, without
	// trailing slash, query, fragment or userinfo. Required; endpoint
	// paths are derived from it.
	Issuer string
	// Resource optionally enables the protected-resource metadata
	// endpoint for this https:// resource URL.
	Resource string
	// Authenticate resolves the host's own browser session into the
	// server-side Authentication acting on /authorize. It must come from
	// the host session — never from client-supplied fields. Nil disables
	// the authorization endpoint.
	Authenticate func(*http.Request) (credbound.Authentication, error)
	// PresentConsent renders the consent (or auto-approval) UI for a
	// validated authorization request; the host later completes it with
	// Manager.CompleteOAuthAuthorization. Nil disables the authorization
	// endpoint.
	PresentConsent func(http.ResponseWriter, *http.Request, credbound.OAuthConsent)
}

// Handler serves the OAuth 2.1/OIDC protocol endpoints for one issuer:
// discovery, protected-resource metadata, JWKS, authorize, token, revoke,
// dynamic client registration and userinfo. Mount it on the host mux; TLS,
// sessions and rate limiting remain the host's responsibility.
type Handler struct {
	manager *credbound.Manager
	config  HandlerConfig
}

// New validates config and returns a Handler for the given Manager. The
// manager is required, Issuer must be a canonical https:// URL, and
// Resource, when set, must be one too.
func New(manager *credbound.Manager, config HandlerConfig) (*Handler, error) {
	if manager == nil || !validHandlerURL(config.Issuer, true) || config.Resource != "" && !validHandlerURL(config.Resource, false) {
		return nil, fmt.Errorf("%w: OAuth manager and issuer are required", credbound.ErrInvalidInput)
	}
	return &Handler{manager: manager, config: config}, nil
}

func validHandlerURL(raw string, issuer bool) bool {
	if raw == "" || raw != strings.TrimSpace(raw) || len(raw) > 2048 {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != raw {
		return false
	}
	return !issuer || !strings.HasSuffix(raw, "/")
}

// ServeHTTP routes the well-known discovery documents and the protocol
// endpoints beneath the issuer path; every other path answers 404.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	issuerPath := endpointPath(h.config.Issuer)
	resourcePath := endpointPath(h.config.Resource)
	switch path {
	case "/.well-known/oauth-authorization-server" + issuerPath, issuerPath + "/.well-known/openid-configuration":
		h.discovery(w, r)
	case "/.well-known/oauth-protected-resource" + resourcePath:
		h.resourceMetadata(w, r)
	case issuerPath + "/.well-known/jwks.json":
		h.jwks(w, r)
	case issuerPath + "/authorize":
		h.authorize(w, r)
	case issuerPath + "/token":
		h.token(w, r)
	case issuerPath + "/revoke":
		h.revoke(w, r)
	case issuerPath + "/register":
		h.register(w, r)
	case issuerPath + "/userinfo":
		h.userInfo(w, r)
	default:
		h.writeError(w, credbound.ErrNotFound)
	}
}

func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	metadata, err := h.manager.OAuthAuthorizationServerMetadata(r.Context(), h.config.Issuer)
	if err != nil {
		h.writeError(w, err)
		return
	}
	if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/.well-known/openid-configuration") && metadata.JWKSURI == "" {
		h.writeError(w, credbound.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (h *Handler) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.config.Resource == "" {
		h.writeError(w, credbound.ErrNotFound)
		return
	}
	metadata, err := h.manager.OAuthProtectedResourceMetadata(r.Context(), h.config.Resource)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, metadata)
}

func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	raw, err := h.manager.OAuthJWKS(r.Context(), h.config.Issuer)
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if h.config.Authenticate == nil || h.config.PresentConsent == nil {
		h.writeError(w, credbound.ErrNotFound)
		return
	}
	query := r.URL.Query()
	redirectURI, state := query.Get("redirect_uri"), query.Get("state")
	if err := h.manager.ValidateOAuthAuthorizationRedirect(r.Context(), h.config.Issuer, query.Get("client_id"), redirectURI); err != nil {
		h.writeError(w, err)
		return
	}
	if query.Get("response_type") != "code" {
		h.writeAuthorizationError(w, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	actor, err := h.config.Authenticate(r)
	if err != nil {
		h.writeAuthorizationError(w, redirectURI, state, "login_required", "interactive authentication is required")
		return
	}
	consent, err := h.manager.BeginOAuthAuthorization(r.Context(), actor, credbound.BeginOAuthAuthorizationInput{
		Issuer: h.config.Issuer, ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"),
		Resource: query.Get("resource"), Scopes: strings.Fields(query.Get("scope")), State: query.Get("state"),
		CodeChallenge: query.Get("code_challenge"), CodeChallengeMethod: query.Get("code_challenge_method"), Nonce: query.Get("nonce"),
	})
	if err != nil {
		code, description := authorizationError(err)
		h.writeAuthorizationError(w, redirectURI, state, code, description)
		return
	}
	h.config.PresentConsent(w, r, consent)
}

func (h *Handler) writeAuthorizationError(w http.ResponseWriter, redirectURI, state, code, description string) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request rejected")
		return
	}
	query := target.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	query.Set("iss", h.config.Issuer)
	target.RawQuery = query.Encode()
	w.Header().Set("Location", target.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

func authorizationError(err error) (string, string) {
	switch {
	case errors.Is(err, credbound.ErrForbidden):
		return "invalid_scope", "requested access is not allowed"
	case errors.Is(err, credbound.ErrUnauthorized):
		return "login_required", "interactive authentication is required"
	case errors.Is(err, credbound.ErrStepUpRequired):
		return "interaction_required", "stronger authentication is required"
	default:
		return "invalid_request", "request rejected"
	}
}

func endpointPath(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "/" {
		return ""
	}
	return path
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	form, err := protocolForm(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	clientID, secret := clientCredentials(r, form)
	grantType := form.Get("grant_type")
	var result credbound.OAuthTokenResponse
	switch grantType {
	case "authorization_code":
		result, err = h.manager.ExchangeOAuthAuthorizationCode(r.Context(), credbound.ExchangeOAuthAuthorizationCodeInput{
			Issuer: h.config.Issuer, ClientID: clientID, ClientSecret: secret, ClientAssertion: form.Get("client_assertion"),
			ClientAssertionType: form.Get("client_assertion_type"),
			Code:                form.Get("code"), RedirectURI: form.Get("redirect_uri"), CodeVerifier: form.Get("code_verifier"), Resource: form.Get("resource"),
		})
	case "refresh_token":
		result, err = h.manager.RefreshOAuthToken(r.Context(), credbound.RefreshOAuthTokenInput{
			Issuer: h.config.Issuer, ClientID: clientID, ClientSecret: secret, ClientAssertion: form.Get("client_assertion"),
			ClientAssertionType: form.Get("client_assertion_type"),
			RefreshToken:        form.Get("refresh_token"), Resource: form.Get("resource"), Scopes: strings.Fields(form.Get("scope")),
		})
	default:
		h.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
		return
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	form, err := protocolForm(w, r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	clientID, secret := clientCredentials(r, form)
	err = h.manager.RevokeOAuthToken(r.Context(), credbound.RevokeOAuthTokenInput{
		Issuer: h.config.Issuer, ClientID: clientID, ClientSecret: secret,
		ClientAssertion: form.Get("client_assertion"), ClientAssertionType: form.Get("client_assertion_type"), Token: form.Get("token"),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	metadata, err := h.manager.OAuthAuthorizationServerMetadata(r.Context(), h.config.Issuer)
	if err != nil || metadata.RegistrationEndpoint == "" {
		h.writeError(w, credbound.ErrNotFound)
		return
	}
	var wire struct {
		ClientName              string                                 `json:"client_name"`
		ApplicationType         credbound.OAuthApplicationType         `json:"application_type"`
		RedirectURIs            []string                               `json:"redirect_uris"`
		GrantTypes              []string                               `json:"grant_types"`
		ResponseTypes           []string                               `json:"response_types"`
		Scope                   string                                 `json:"scope"`
		TokenEndpointAuthMethod credbound.OAuthTokenEndpointAuthMethod `json:"token_endpoint_auth_method"`
		JWKSURI                 string                                 `json:"jwks_uri"`
		JWKS                    json.RawMessage                        `json:"jwks"`
	}
	if err := decodeJSON(w, r, &wire); err != nil {
		h.writeError(w, err)
		return
	}
	initial := bearerToken(r)
	issued, err := h.manager.RegisterOAuthClient(r.Context(), h.config.Issuer, initial, credbound.OAuthClientRegistrationInput{
		Name: wire.ClientName, ApplicationType: wire.ApplicationType, RedirectURIs: wire.RedirectURIs,
		GrantTypes: wire.GrantTypes, ResponseTypes: wire.ResponseTypes, Scopes: strings.Fields(wire.Scope),
		TokenEndpointAuthMethod: wire.TokenEndpointAuthMethod, JWKSURI: wire.JWKSURI, JWKS: wire.JWKS,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	response := map[string]any{
		"client_id": issued.Client.ClientID, "client_name": issued.Client.Name,
		"application_type": issued.Client.ApplicationType, "redirect_uris": issued.Client.RedirectURIs,
		"grant_types": issued.Client.GrantTypes, "response_types": issued.Client.ResponseTypes,
		"scope": strings.Join(issued.Client.Scopes, " "), "token_endpoint_auth_method": issued.Client.TokenEndpointAuthMethod,
	}
	if issued.ClientSecret != "" {
		response["client_secret"] = issued.ClientSecret
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, response)
}

func (h *Handler) userInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet, http.MethodPost)
		return
	}
	info, err := h.manager.OAuthUserInfo(r.Context(), h.config.Issuer, bearerToken(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// Protect wraps next with bearer-token validation at the resource boundary.
// resource is the canonical protected-resource identifier registered with the
// manager, requiredScope the minimum scope for this route, and metadataURL the
// absolute URL of the resource's protected-resource metadata document echoed
// in WWW-Authenticate challenges. Mount it per route:
//
//	mux.Handle("/mcp", oauthhttp.Protect(manager,
//		"https://api.example.com/mcp", // resource
//		"mcp.read",                    // requiredScope
//		"https://api.example.com/.well-known/oauth-protected-resource", // metadataURL
//		mcpHandler))
func Protect(manager *credbound.Manager, resource, requiredScope, metadataURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authentication, err := manager.AuthenticateOAuthAccessToken(r.Context(), resource, bearerToken(r))
		if err != nil {
			w.Header().Set("WWW-Authenticate", bearerChallenge(metadataURL, requiredScope, ""))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !authentication.HasScope(requiredScope) {
			w.Header().Set("WWW-Authenticate", bearerChallenge(metadataURL, requiredScope, "insufficient_scope"))
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithAuthentication(r.Context(), authentication)))
	})
}

type authenticationKey struct{}

// WithAuthentication returns a context carrying a verified OAuth
// authentication, as installed by Protect for its wrapped handler. Only
// attach values produced by Credbound's token authentication — downstream
// authorization decisions trust them.
func WithAuthentication(ctx context.Context, authentication credbound.OAuthAuthentication) context.Context {
	return context.WithValue(ctx, authenticationKey{}, authentication)
}

// AuthenticationFromContext extracts the verified OAuth authentication that
// Protect attached to the request, reporting false when the request did not
// pass through Protect.
func AuthenticationFromContext(r *http.Request) (credbound.OAuthAuthentication, bool) {
	value, ok := r.Context().Value(authenticationKey{}).(credbound.OAuthAuthentication)
	return value, ok
}

func protocolForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxProtocolBody)
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("%w: invalid form body", credbound.ErrInvalidInput)
	}
	return r.PostForm, nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxProtocolBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: invalid JSON body", credbound.ErrInvalidInput)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON value", credbound.ErrInvalidInput)
	}
	return nil
}

func clientCredentials(r *http.Request, form url.Values) (string, string) {
	clientID, secret, ok := r.BasicAuth()
	if ok {
		return clientID, secret
	}
	return form.Get("client_id"), form.Get("client_secret")
}

func bearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}

func bearerChallenge(metadataURL, scope, problem string) string {
	parts := []string{}
	if metadataURL != "" {
		parts = append(parts, `resource_metadata=`+quoteAuthParam(metadataURL))
	}
	if scope != "" {
		parts = append(parts, `scope=`+quoteAuthParam(scope))
	}
	if problem != "" {
		parts = append(parts, `error=`+quoteAuthParam(problem))
	}
	if len(parts) == 0 {
		return "Bearer"
	}
	return "Bearer " + strings.Join(parts, ", ")
}

// quoteAuthParam renders value as an RFC 9110 quoted-string for a
// WWW-Authenticate challenge: double-quote and backslash are backslash-escaped
// so a value carrying either (a resource_metadata URL with query parameters,
// say) stays a single well-formed parameter instead of being silently mangled.
// Control characters are dropped so nothing can break the header.
func quoteAuthParam(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if r == '"' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String()
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credbound.ErrNotFound), errors.Is(err, credbound.ErrNotSupported):
		h.writeOAuthError(w, http.StatusNotFound, "invalid_request", "resource not found")
	case errors.Is(err, credbound.ErrInvalidCredentials), errors.Is(err, credbound.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", "Basic realm=\"oauth\"")
		h.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
	case errors.Is(err, credbound.ErrForbidden):
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested access is not allowed")
	case errors.Is(err, credbound.ErrExpired):
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "credential expired")
	default:
		h.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "request rejected")
	}
}

func (h *Handler) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func methodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	w.WriteHeader(http.StatusMethodNotAllowed)
}
