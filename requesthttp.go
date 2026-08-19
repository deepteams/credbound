package credbound

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// HTTPRequestMetadata wraps next so that every request context carries the
// client's RequestMetadata — IP address and User-Agent — which audit events
// recorded while serving the request then pick up automatically.
//
// Without trusted proxies the client address is the transport peer from
// RemoteAddr and no header is read, so a client can never influence what
// the audit chain records. When the peer belongs to one of the trusted
// prefixes, the rightmost X-Forwarded-For address outside every trusted
// prefix is used instead: entries appended by the host's own proxies are
// skipped, and entries a client forged beyond them are never reached. A
// malformed entry stops the walk and the peer address is recorded, failing
// toward an address the client cannot choose.
func HTTPRequestMetadata(next http.Handler, trustedProxies ...netip.Prefix) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metadata := RequestMetadata{
			IPAddress: clientAddress(r, trustedProxies),
			UserAgent: r.UserAgent(),
		}
		next.ServeHTTP(w, r.WithContext(WithRequestMetadata(r.Context(), metadata)))
	})
}

func clientAddress(r *http.Request, trustedProxies []netip.Prefix) string {
	peer, ok := parseHostAddr(r.RemoteAddr)
	if !ok {
		return ""
	}
	if !addrInPrefixes(peer, trustedProxies) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		address, ok := parseHostAddr(hop)
		if !ok {
			break
		}
		if !addrInPrefixes(address, trustedProxies) {
			return address.String()
		}
	}
	return peer.String()
}

// parseHostAddr parses an IP address that may carry a port or brackets, as
// found in RemoteAddr and occasionally in X-Forwarded-For entries.
func parseHostAddr(value string) (netip.Addr, bool) {
	host := value
	if splitHost, _, err := net.SplitHostPort(value); err == nil {
		host = splitHost
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap().WithZone(""), true
}

func addrInPrefixes(address netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
