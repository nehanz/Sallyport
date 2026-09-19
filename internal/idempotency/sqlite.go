package idempotency

import (
	"context"
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS webhook_claims (
			key        TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return nil, err
	}

	_, _ = db.Exec(`DELETE FROM webhook_claims WHERE expires_at < ?`, time.Now().Unix())

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	exp := time.Now().Add(ttl).Unix()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webhook_claims (key, expires_at) VALUES (?, ?)`,
		key, exp,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *SQLiteStore) Release(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM webhook_claims WHERE key = ?`, key,
	)
	return err
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
