package sallyport

import (
	"context"
	"time"

	"github.com/nehanz/sallyport/internal/idempotency"
)

type Store interface {
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
	Release(ctx context.Context, key string) error
}

func NewMemoryStore() Store {
	return idempotency.NewMemoryStore()
}

func NewSQLiteStore(path string) (*idempotency.SQLiteStore, error) {
	return idempotency.NewSQLiteStore(path)
}
