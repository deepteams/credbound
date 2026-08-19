package credbound

import (
	"context"
	"net"
	"net/netip"
	"strings"
)

type requestMetadataKey struct{}

const (
	maxAuditIPLength        = 64
	maxAuditUserAgentLength = 256
)

// WithRequestMetadata returns a context that carries the client network
// context for every audit event recorded while serving the request. The host
// service is responsible for resolving the real client address from its
// trusted proxy configuration before attaching it.
func WithRequestMetadata(ctx context.Context, metadata RequestMetadata) context.Context {
	return context.WithValue(ctx, requestMetadataKey{}, sanitizeRequestMetadata(metadata))
}

// TrustedRequestFromAddr derives a TrustedRequest from the transport peer
// address (typically http.Request.RemoteAddr): Local is set only when the
// peer is a loopback address. Always call it with the actual network peer —
// never with a value copied from a request parameter, header, or body, which
// a client controls. Requests arriving through a reverse proxy have the proxy
// as their peer and are correctly reported as non-local.
func TrustedRequestFromAddr(remoteAddr string) TrustedRequest {
	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return TrustedRequest{}
	}
	return TrustedRequest{Local: address.IsLoopback()}
}

func requestMetadataFromContext(ctx context.Context) RequestMetadata {
	metadata, _ := ctx.Value(requestMetadataKey{}).(RequestMetadata)
	return metadata
}

func sanitizeRequestMetadata(metadata RequestMetadata) RequestMetadata {
	return RequestMetadata{
		IPAddress: sanitizeAuditField(metadata.IPAddress, maxAuditIPLength),
		UserAgent: sanitizeAuditField(metadata.UserAgent, maxAuditUserAgentLength),
	}
}

func sanitizeAuditField(value string, limit int) string {
	value = strings.TrimSpace(value)
	cleaned := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	runes := []rune(cleaned)
	if len(runes) > limit {
		return string(runes[:limit])
	}
	return cleaned
}
