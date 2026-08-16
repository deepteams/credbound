// Package oauthhttp provides optional OAuth/OIDC and MCP HTTP adapters for Credbound.
package oauthhttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/deepteams/credbound"
)

const maxMetadataDocument = 5 << 10

type MetadataFetcher struct {
	client *http.Client
	now    func() time.Time
	limit  chan struct{}
}

func NewMetadataFetcher(timeout time.Duration, concurrency int) (*MetadataFetcher, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if concurrency <= 0 {
		concurrency = 16
	}
	if concurrency > 256 {
		return nil, fmt.Errorf("%w: CIMD concurrency is limited to 256", credbound.ErrInvalidInput)
	}
	fetcher := &MetadataFetcher{now: time.Now, limit: make(chan struct{}, concurrency)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = fetcher.dialContext
	transport.MaxConnsPerHost = 4
	transport.ResponseHeaderTimeout = timeout
	transport.TLSHandshakeTimeout = timeout
	fetcher.client = &http.Client{
		Timeout:       timeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return fetcher, nil
}

func (f *MetadataFetcher) Fetch(ctx context.Context, clientID string) (credbound.OAuthClientMetadataDocument, error) {
	select {
	case f.limit <- struct{}{}:
		defer func() { <-f.limit }()
	case <-ctx.Done():
		return credbound.OAuthClientMetadataDocument{}, ctx.Err()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: invalid Client Identifier URL", credbound.ErrInvalidInput)
	}
	request.Header.Set("Accept", "application/json")
	response, err := f.client.Do(request)
	if err != nil {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("fetch CIMD: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: CIMD returned HTTP %d", credbound.ErrInvalidCredentials, response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: CIMD must be application/json", credbound.ErrInvalidInput)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataDocument+1))
	if err != nil || len(raw) > maxMetadataDocument {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: CIMD exceeds 5 KiB", credbound.ErrInvalidInput)
	}
	var wire struct {
		ClientID                string                                 `json:"client_id"`
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
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil || wire.ClientID != clientID || wire.ClientName == "" || len(wire.ClientName) > 200 || len(wire.RedirectURIs) == 0 {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: invalid CIMD document", credbound.ErrInvalidInput)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return credbound.OAuthClientMetadataDocument{}, fmt.Errorf("%w: trailing CIMD value", credbound.ErrInvalidInput)
	}
	now := f.now().UTC()
	return credbound.OAuthClientMetadataDocument{
		ClientID: wire.ClientID, ClientName: wire.ClientName, ApplicationType: wire.ApplicationType,
		RedirectURIs: wire.RedirectURIs, GrantTypes: wire.GrantTypes, ResponseTypes: wire.ResponseTypes,
		Scope: wire.Scope, TokenEndpointAuthMethod: wire.TokenEndpointAuthMethod,
		JWKSURI: wire.JWKSURI, JWKS: wire.JWKS, FetchedAt: now, ExpiresAt: now.Add(cacheLifetime(response.Header.Get("Cache-Control"))),
	}, nil
}

func (f *MetadataFetcher) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, fmt.Errorf("resolve CIMD host: %w", err)
	}
	for _, address := range addresses {
		if !publicAddress(address) {
			return nil, fmt.Errorf("CIMD host resolves to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: f.client.Timeout, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].String(), port))
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, raw := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001:db8::/32", "2001::/23", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		if netip.MustParsePrefix(raw).Contains(address) {
			return false
		}
	}
	return true
}

func cacheLifetime(value string) time.Duration {
	duration := 5 * time.Minute
	for _, directive := range strings.Split(value, ",") {
		name, raw, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if ok && strings.EqualFold(name, "max-age") {
			seconds, err := strconv.Atoi(strings.Trim(raw, `"`))
			if err == nil {
				duration = time.Duration(seconds) * time.Second
			}
		}
	}
	if duration < time.Minute {
		return time.Minute
	}
	if duration > time.Hour {
		return time.Hour
	}
	return duration
}

var _ credbound.OAuthClientMetadataFetcher = (*MetadataFetcher)(nil)
