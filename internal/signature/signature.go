package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

var ErrInvalidSignature = errors.New("invalid signature")

func Verify(payload []byte, secret, msgID, timestamp, sigHeader string) error {
	signed := msgID + "." + timestamp + "." + string(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !verifyAnySignature(sigHeader, expected) {
		return ErrInvalidSignature
	}
	return nil
}

func verifyAnySignature(header, expected string) bool {
	for _, part := range strings.Fields(header) {
		if !strings.HasPrefix(part, "v1,") {
			continue
		}
		sig := strings.TrimPrefix(part, "v1,")
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return true
		}
	}
	return false
}
