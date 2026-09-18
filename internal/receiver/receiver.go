package receiver

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "log"
    "net/http"
)

func Handler(secret string) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        body, err := io.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "read error", http.StatusBadRequest)
            return
        }

        sig := r.Header.Get("X-Webhook-Signature")
        if sig == "" {
            log.Println("REJECTED: missing signature header")
            http.Error(w, "missing signature", http.StatusUnauthorized)
            return
        }

        mac := hmac.New(sha256.New, []byte(secret))
        mac.Write(body)
        expected := hex.EncodeToString(mac.Sum(nil))

        if sig == expected {
            log.Println("ACCEPTED: signature valid")
            w.WriteHeader(http.StatusOK)
            return
        }

        log.Println("REJECTED: signature mismatch")
        http.Error(w, "invalid signature", http.StatusUnauthorized)
    })
}
