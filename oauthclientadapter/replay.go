package oauthclientadapter

import (
	"context"
	"sync"
	"time"
)

// MemoryReplayStore is suitable for a single-process host. Multi-process hosts
// must use a shared store with an atomic insert-if-absent operation.
type MemoryReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
	now     func() time.Time
}

func NewMemoryReplayStore(clock func() time.Time) *MemoryReplayStore {
	if clock == nil {
		clock = time.Now
	}
	return &MemoryReplayStore{entries: make(map[string]time.Time), now: func() time.Time { return clock().UTC() }}
}

func (s *MemoryReplayStore) Use(ctx context.Context, clientID, jwtID string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiry := range s.entries {
		if !now.Before(expiry) {
			delete(s.entries, key)
		}
	}
	key := clientID + "\x00" + jwtID
	if _, exists := s.entries[key]; exists {
		return false, nil
	}
	s.entries[key] = expiresAt.UTC()
	return true, nil
}

var _ AssertionReplayStore = (*MemoryReplayStore)(nil)
