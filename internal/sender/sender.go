package sender

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "net/http"
)

func SignAndSend(url, secret string, payload []byte) (*http.Response, error) {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    sig := hex.EncodeToString(mac.Sum(nil))

    req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
    if err != nil {
        return nil, err
    }
    req.Header.Set("X-Webhook-Signature", sig)
    req.Header.Set("Content-Type", "application/json")

    return http.DefaultClient.Do(req)
}

func SignAndSendTampered(url, secret string, payload []byte) (*http.Response, error) {
    wrong := append([]byte("tampered:"), payload...)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(wrong)
    sig := hex.EncodeToString(mac.Sum(nil))
    req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
    if err != nil {
        return nil, err
    }
    req.Header.Set("X-Webhook-Signature", sig)
    req.Header.Set("Content-Type", "application/json")

    return http.DefaultClient.Do(req)
}
