package credbound

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestHTTPRequestMetadata(t *testing.T) {
	private := netip.MustParsePrefix("10.0.0.0/8")
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		proxies    []netip.Prefix
		wantIP     string
	}{
		{name: "peer without proxies", remoteAddr: "203.0.113.7:1234", forwarded: []string{"198.51.100.9"}, wantIP: "203.0.113.7"},
		{name: "trusted proxy resolves forwarded client", remoteAddr: "10.0.0.1:443", forwarded: []string{"198.51.100.9, 10.0.0.2"}, proxies: []netip.Prefix{private}, wantIP: "198.51.100.9"},
		{name: "multiple forwarded headers", remoteAddr: "10.0.0.1:443", forwarded: []string{"198.51.100.9", "10.0.0.2"}, proxies: []netip.Prefix{private}, wantIP: "198.51.100.9"},
		{name: "every hop trusted falls back to peer", remoteAddr: "10.0.0.1:443", forwarded: []string{"10.0.0.9"}, proxies: []netip.Prefix{private}, wantIP: "10.0.0.1"},
		{name: "malformed hop fails toward the peer", remoteAddr: "10.0.0.1:443", forwarded: []string{"198.51.100.9, not-an-ip"}, proxies: []netip.Prefix{private}, wantIP: "10.0.0.1"},
		{name: "untrusted peer ignores forwarded header", remoteAddr: "203.0.113.7:1234", forwarded: []string{"198.51.100.9"}, proxies: []netip.Prefix{private}, wantIP: "203.0.113.7"},
		{name: "ipv6 peer with zone and port", remoteAddr: "[fe80::1%25eth0]:8080", wantIP: "fe80::1"},
		{name: "unparsable peer records nothing", remoteAddr: "@", wantIP: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var seen RequestMetadata
			handler := HTTPRequestMetadata(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = requestMetadataFromContext(r.Context())
			}), test.proxies...)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("User-Agent", "audit-probe/1.0")
			for i, value := range test.forwarded {
				if i == 0 {
					request.Header.Set("X-Forwarded-For", value)
				} else {
					request.Header.Add("X-Forwarded-For", value)
				}
			}
			handler.ServeHTTP(httptest.NewRecorder(), request)
			if seen.IPAddress != test.wantIP {
				t.Fatalf("IPAddress = %q, want %q", seen.IPAddress, test.wantIP)
			}
			if test.wantIP != "" && seen.UserAgent != "audit-probe/1.0" {
				t.Fatalf("UserAgent = %q", seen.UserAgent)
			}
		})
	}
}
