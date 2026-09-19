package sallyport

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nehanz/sallyport/internal/signature"
)

type Config struct {
	Secret    string
	Tolerance time.Duration
}

func New(cfg Config, next http.Handler) http.Handler {
	if cfg.Tolerance == 0 {
		cfg.Tolerance = 5 * time.Minute
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

		if err := signature.Verify(body, cfg.Secret, msgID, tsStr, sigHeader); err != nil {
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
