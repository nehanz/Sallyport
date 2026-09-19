package sender

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func NewRequest(url, secret string, payload []byte) (*http.Request, error) {
	msgID := "msg_" + randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	signed := msgID + "." + ts + "." + string(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sig)
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}

func SignRequest(url, secret string, payload []byte) (*http.Request, error) {
	return NewRequest(url, secret, payload)
}

func SignAndSend(url, secret string, payload []byte) (*http.Response, error) {
	req, err := NewRequest(url, secret, payload)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func SignAndSendTampered(url, secret string, payload []byte) (*http.Response, error) {
	msgID := "msg_" + randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	wrong := append([]byte("tampered:"), payload...)
	signed := msgID + "." + ts + "." + string(wrong)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("webhook-id", msgID)
	req.Header.Set("webhook-timestamp", ts)
	req.Header.Set("webhook-signature", sig)
	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}
