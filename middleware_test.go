package sallyport

import (
    "bytes"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/nehanz/sallyport/internal/receiver"
    "github.com/nehanz/sallyport/internal/sender"
)

const testSecret = "whsec_test_secret"

func TestBasicVerification(t *testing.T) {
    // start a test server with the naive receiver
    srv := httptest.NewServer(receiver.Handler(testSecret))
    defer srv.Close()

    payload := []byte(`{"event":"payment.succeeded","amount":100}`)

    tests := []struct {
        name       string
        send       func() (*http.Response, error)
        wantStatus int
    }{
        {
            name: "valid signature",
            send: func() (*http.Response, error) {
                return sender.SignAndSend(srv.URL, testSecret, payload)
            },
            wantStatus: http.StatusOK,
        },
        {
            name: "tampered signature",
            send: func() (*http.Response, error) {
                return sender.SignAndSendTampered(srv.URL, testSecret, payload)
            },
            wantStatus: http.StatusUnauthorized,
        },
        {
            name: "missing signature",
            send: func() (*http.Response, error) {
                return http.Post(srv.URL, "application/json", bytes.NewReader(payload))
            },
            wantStatus: http.StatusUnauthorized,
        },
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            resp, err := tc.send()
            if err != nil {
                t.Fatalf("send failed: %v", err)
            }
            defer resp.Body.Close()
            if resp.StatusCode != tc.wantStatus {
                t.Errorf("got status %d, want %d", resp.StatusCode, tc.wantStatus)
            }
        })
    }
}
