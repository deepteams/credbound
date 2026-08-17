package credbound

import (
	"context"
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
