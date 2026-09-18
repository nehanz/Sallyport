package sallyport

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Secret     string
	Tolerance  time.Duration
	HeaderName string
}

func New(cfg Config) func(http.Handler) http.Handler {
	if cfg.Tolerance == 0 {
		cfg.Tolerance = 5 * time.Minute
	}
	if cfg.HeaderName == "" {
		cfg.HeaderName = "Webhook-Signature"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sigHeader := r.Header.Get(cfg.HeaderName)
			if sigHeader == "" {
				http.Error(w, "Missing signature header", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(sigHeader, ",")
			var timestampStr, signatureStr string
			for _, part := range parts {
				if strings.HasPrefix(part, "t=") {
					timestampStr = strings.TrimPrefix(part, "t=")
				} else if strings.HasPrefix(part, "v1=") {
					signatureStr = strings.TrimPrefix(part, "v1=")
				}
			}

			if timestampStr == "" || signatureStr == "" {
				http.Error(w, "Invalid signature header format", http.StatusUnauthorized)
				return
			}

			ts, err := strconv.ParseInt(timestampStr, 10, 64)
			if err != nil {
				http.Error(w, "Invalid timestamp format", http.StatusUnauthorized)
				return
			}

			webhookTime := time.Unix(ts, 0)
			if time.Since(webhookTime) > cfg.Tolerance || time.Until(webhookTime) > cfg.Tolerance {
				http.Error(w, "Timestamp outside tolerance zone", http.StatusUnauthorized)
				return
			}
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusInternalServerError)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			payload := timestampStr + "." + string(bodyBytes)

			mac := hmac.New(sha256.New, []byte(cfg.Secret))
			mac.Write([]byte(payload))
			expectedMAC := mac.Sum(nil)
			providedMAC, err := hex.DecodeString(signatureStr)
			if err != nil {
				http.Error(w, "Invalid signature hex format", http.StatusUnauthorized)
				return
			}

			if !hmac.Equal(providedMAC, expectedMAC) {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
