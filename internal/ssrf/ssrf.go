// Package ssrf holds the outbound-fetch address policy shared by the
// adapters that dereference configured URLs on behalf of a host: OAuth
// Client Identifier Metadata Documents (oauthhttp), private_key_jwt JWKS
// documents (oauthclientadapter), and SAML IdP metadata (samladapter).
// Only globally routable unicast addresses may be dialed, so a hostname
// resolving into loopback, private, link-local, CGNAT or reserved ranges
// cannot be used to reach internal services.
package ssrf

import (
	"net"
	"net/netip"
)

// blockedPrefixes lists the ranges net/netip's classification helpers do
// not cover: netip.Addr.IsPrivate covers only the RFC 1918 / ULA ranges,
// so CGNAT (100.64.0.0/10), the reserved and TEST-NET blocks, benchmarking
// space and 240.0.0.0/4 must be rejected explicitly or a URL resolving into
// them could reach internal services (cloud metadata behind CGNAT,
// carrier-internal hosts).
var blockedPrefixes = func() []netip.Prefix {
	raw := []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"2001:db8::/32", "2001::/23", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	prefixes := make([]netip.Prefix, len(raw))
	for index, value := range raw {
		prefixes[index] = netip.MustParsePrefix(value)
	}
	return prefixes
}()

// PublicAddress reports whether address is globally routable unicast and
// therefore safe to dial for a host-configured URL fetch.
func PublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// PublicIP adapts PublicAddress to the net.IP values returned by
// net.Resolver.LookupIPAddr.
func PublicIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	return ok && PublicAddress(address)
}
