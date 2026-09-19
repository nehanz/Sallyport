package idempotency

import (
	"context"
	"time"
)

type Store interface {
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)

	Release(ctx context.Context, key string) error
}
