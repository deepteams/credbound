package credbound

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '7' {
		return false
	}
	if !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func validSSOProviderKind(kind SSOProviderKind) bool {
	switch kind {
	case SSOProviderGoogle, SSOProviderGitHub, SSOProviderMicrosoft, SSOProviderOIDC, SSOProviderSAML:
		return true
	default:
		return false
	}
}

func randomBytes(source io.Reader, size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := io.ReadFull(source, b); err != nil {
		return nil, fmt.Errorf("read secure randomness: %w", err)
	}
	return b, nil
}

func (m *Manager) newID() (string, error) {
	// UUIDv7 layout from RFC 9562: 48-bit Unix milliseconds, version 7,
	// 12-bit monotonic sequence, RFC variant, then 62 random bits.
	m.idMu.Lock()
	defer m.idMu.Unlock()
	now := m.now().UnixMilli()
	if now > m.idUnixMilli {
		m.idUnixMilli = now
		m.idSequence = 0
	} else if m.idSequence == 0x0fff {
		m.idUnixMilli++
		m.idSequence = 0
	} else {
		m.idSequence++
	}
	b, err := randomBytes(m.random, 16)
	if err != nil {
		return "", err
	}
	timestamp := uint64(m.idUnixMilli)
	for index := 5; index >= 0; index-- {
		b[index] = byte(timestamp)
		timestamp >>= 8
	}
	b[6] = 0x70 | byte(m.idSequence>>8)
	b[7] = byte(m.idSequence)
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func digest(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

func (m *Manager) seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.secretKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	nonce, err := randomBytes(m.random, gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...), nil
}

func (m *Manager) open(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.secretKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrInvalidCredentials
	}
	plaintext, err := gcm.Open(nil, ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():], nil)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	return plaintext, nil
}

type ceremonyContinuation struct {
	UserID    string    `json:"uid"`
	Operation string    `json:"op"`
	Name      string    `json:"name,omitempty"`
	ExpiresAt time.Time `json:"exp"`
	Session   []byte    `json:"session"`
}

func (m *Manager) encodeContinuation(value ceremonyContinuation) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal continuation: %w", err)
	}
	sealed, err := m.seal(payload)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (m *Manager) decodeContinuation(raw, operation string) (ceremonyContinuation, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ceremonyContinuation{}, ErrInvalidCredentials
	}
	payload, err := m.open(sealed)
	if err != nil {
		return ceremonyContinuation{}, ErrInvalidCredentials
	}
	var value ceremonyContinuation
	if err := json.Unmarshal(payload, &value); err != nil || value.Operation != operation || value.UserID == "" {
		return ceremonyContinuation{}, ErrInvalidCredentials
	}
	if !m.now().Before(value.ExpiresAt) {
		return ceremonyContinuation{}, ErrExpired
	}
	return value, nil
}
