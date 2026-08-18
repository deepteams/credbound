package ssrf

import (
	"net"
	"net/netip"
	"testing"
)

func TestPublicAddressBlocksNonRoutableRanges(t *testing.T) {
	blocked := []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.1.1", "169.254.169.254", "224.0.0.1", "255.255.255.255",
		// Ranges the netip classification helpers do not cover.
		"100.64.0.1", "100.127.255.255", "192.0.0.1", "192.0.2.5", "198.18.0.1",
		"198.51.100.7", "203.0.113.9", "240.0.0.1",
		"::", "::1", "fe80::1", "fc00::1", "fd12::1", "ff02::1", "2001:db8::1", "2001:0::1",
	}
	for _, raw := range blocked {
		if PublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("non-public address accepted: %q", raw)
		}
	}
	for _, raw := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"} {
		if !PublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("public address rejected: %q", raw)
		}
	}
	// IPv4-mapped IPv6 forms must classify as their embedded IPv4 address.
	if PublicAddress(netip.MustParseAddr("::ffff:10.0.0.1")) {
		t.Fatal("mapped private address accepted")
	}
	if !PublicAddress(netip.MustParseAddr("::ffff:8.8.8.8")) {
		t.Fatal("mapped public address rejected")
	}
}

func TestPublicIPAdaptsResolverOutput(t *testing.T) {
	if PublicIP(nil) {
		t.Fatal("nil IP accepted")
	}
	if PublicIP(net.ParseIP("192.168.1.1")) {
		t.Fatal("private IP accepted")
	}
	if !PublicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public IP rejected")
	}
}
