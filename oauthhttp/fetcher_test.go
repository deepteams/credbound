package oauthhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/deepteams/credbound"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func metadataResponse(status int, contentType, cacheControl, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header: http.Header{
			"Content-Type":  []string{contentType},
			"Cache-Control": []string{cacheControl},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

func TestMetadataFetcherDocumentValidation(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	clientID := "https://client.example.com/metadata.json"
	valid := `{"client_id":"https://client.example.com/metadata.json","client_name":"Example","application_type":"web","redirect_uris":["https://client.example.com/callback"],"grant_types":["authorization_code"],"response_types":["code"],"scope":"openid","token_endpoint_auth_method":"none"}`
	response := metadataResponse(http.StatusOK, "application/json; charset=utf-8", "public, max-age=900", valid)
	fetcher := &MetadataFetcher{
		client: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("Accept") != "application/json" {
				t.Error("missing JSON accept header")
			}
			return response, nil
		})},
		now: func() time.Time { return now }, limit: make(chan struct{}, 1),
	}
	document, err := fetcher.Fetch(t.Context(), clientID)
	if err != nil {
		t.Fatal(err)
	}
	if document.ClientID != clientID || !document.FetchedAt.Equal(now) || !document.ExpiresAt.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("document = %#v", document)
	}

	cases := []struct {
		name         string
		response     *http.Response
		transportErr error
		target       error
	}{
		{name: "transport", transportErr: errors.New("offline")},
		{name: "status", response: metadataResponse(http.StatusFound, "application/json", "", valid), target: credbound.ErrInvalidCredentials},
		{name: "media type", response: metadataResponse(http.StatusOK, "text/plain", "", valid), target: credbound.ErrInvalidInput},
		{name: "large", response: metadataResponse(http.StatusOK, "application/json", "", strings.Repeat("x", maxMetadataDocument+1)), target: credbound.ErrInvalidInput},
		{name: "invalid json", response: metadataResponse(http.StatusOK, "application/json", "", `{`), target: credbound.ErrInvalidInput},
		{name: "wrong id", response: metadataResponse(http.StatusOK, "application/json", "", strings.Replace(valid, clientID, "https://other.example.com", 1)), target: credbound.ErrInvalidInput},
		{name: "unknown field", response: metadataResponse(http.StatusOK, "application/json", "", strings.TrimSuffix(valid, "}")+`,"extra":true}`), target: credbound.ErrInvalidInput},
		{name: "trailing value", response: metadataResponse(http.StatusOK, "application/json", "", valid+` {}`), target: credbound.ErrInvalidInput},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fetcher := &MetadataFetcher{
				client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return test.response, test.transportErr })},
				now:    time.Now, limit: make(chan struct{}, 1),
			}
			_, err := fetcher.Fetch(t.Context(), clientID)
			if test.target != nil && !errors.Is(err, test.target) {
				t.Fatalf("Fetch() = %v, want %v", err, test.target)
			}
			if test.target == nil && err == nil {
				t.Fatal("Fetch() unexpectedly succeeded")
			}
		})
	}
}

func TestMetadataFetcherPolicyHelpers(t *testing.T) {
	if _, err := NewMetadataFetcher(time.Second, 257); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("concurrency = %v", err)
	}
	if fetcher, err := NewMetadataFetcher(0, 0); err != nil || fetcher.client.Timeout != 5*time.Second || cap(fetcher.limit) != 16 {
		t.Fatalf("defaults = %#v, %v", fetcher, err)
	}

	blocked := &MetadataFetcher{client: http.DefaultClient, now: time.Now, limit: make(chan struct{}, 1)}
	blocked.limit <- struct{}{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := blocked.Fetch(ctx, "https://client.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked fetch = %v", err)
	}
	open := &MetadataFetcher{client: http.DefaultClient, now: time.Now, limit: make(chan struct{}, 1)}
	if _, err := open.Fetch(t.Context(), "://bad"); !errors.Is(err, credbound.ErrInvalidInput) {
		t.Fatalf("invalid URL = %v", err)
	}
	if _, err := open.dialContext(t.Context(), "tcp", "missing-port"); err == nil {
		t.Fatal("invalid dial address accepted")
	}
	if _, err := open.dialContext(t.Context(), "tcp", "127.0.0.1:443"); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("loopback dial = %v", err)
	}

	for value, want := range map[string]time.Duration{
		"":                       5 * time.Minute,
		"max-age=1":              time.Minute,
		`public, max-age="7200"`: time.Hour,
		"max-age=invalid":        5 * time.Minute,
		"MAX-AGE=120":            2 * time.Minute,
	} {
		if got := cacheLifetime(value); got != want {
			t.Fatalf("cacheLifetime(%q) = %v, want %v", value, got, want)
		}
	}
	if publicAddress(netip.Addr{}) {
		t.Fatal("invalid address accepted")
	}
	for _, raw := range []string{"127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "192.0.2.1", "2001:db8::1"} {
		if publicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %s", raw)
		}
	}
	if !publicAddress(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
}
