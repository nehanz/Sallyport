package idempotency

import (
	"context"
	"sync"
	"time"
)

type MemoryStore struct {
	mu     sync.Mutex
	claims map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		claims: make(map[string]time.Time),
	}
}

func (m *MemoryStore) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	for k, exp := range m.claims {
		if now.After(exp) {
			delete(m.claims, k)
		}
	}

	if _, exists := m.claims[key]; exists {
		return false, nil
	}

	m.claims[key] = now.Add(ttl)
	return true, nil
}

func (m *MemoryStore) Release(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.claims, key)
	return nil
}
