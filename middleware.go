package sallyport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nehanz/sallyport/internal/idempotency"
	"github.com/nehanz/sallyport/internal/signature"
)

type Config struct {
	Secret      string
	Secrets     []string
	Tolerance   time.Duration
	Idempotency idempotency.Store
	ClaimTTL    time.Duration
}

type contextKey int

const matchedSecretKey contextKey = 1

func MatchedSecret(ctx context.Context) string {
	if v, ok := ctx.Value(matchedSecretKey).(string); ok {
		return v
	}
	return ""
}

func New(cfg Config, next http.Handler) http.Handler {
	if len(cfg.Secrets) == 0 && cfg.Secret != "" {
		cfg.Secrets = []string{cfg.Secret}
	}
	if len(cfg.Secrets) == 0 {
		panic("sallyport: at least one secret is required")
	}
	if cfg.Tolerance == 0 {
		cfg.Tolerance = 5 * time.Minute
	}
	if cfg.ClaimTTL == 0 {
		cfg.ClaimTTL = 24 * time.Hour
	}
	if cfg.Idempotency == nil {
		panic("sallyport: Idempotency store is required")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		msgID := r.Header.Get("webhook-id")
		tsStr := r.Header.Get("webhook-timestamp")
		sigHeader := r.Header.Get("webhook-signature")

		if msgID == "" || tsStr == "" || sigHeader == "" {
			http.Error(w, "missing headers", http.StatusUnauthorized)
			return
		}

		ts, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid timestamp", http.StatusUnauthorized)
			return
		}
		age := time.Since(time.Unix(ts, 0))
		if age > cfg.Tolerance || age < -cfg.Tolerance {
			http.Error(w, "timestamp outside tolerance", http.StatusUnauthorized)
			return
		}

		var matched string
		for _, s := range cfg.Secrets {
			if signature.Verify(body, s, msgID, tsStr, sigHeader) == nil {
				matched = s
				break
			}
		}
		if matched == "" {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		claimed, err := cfg.Idempotency.Claim(r.Context(), msgID, cfg.ClaimTTL)
		if err != nil {
			http.Error(w, "idempotency error", http.StatusInternalServerError)
			return
		}
		if !claimed {
			w.WriteHeader(http.StatusOK)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), matchedSecretKey, matched))

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		if rec.status >= 500 {
			cfg.Idempotency.Release(r.Context(), msgID)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
