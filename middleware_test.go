package sallyport

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/nehanz/sallyport/internal/sender"
)

const testSecret = "whsec_test_secret"

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware(t *testing.T) {
	srv := httptest.NewServer(New(Config{Secret: testSecret}, okHandler()))
	defer srv.Close()

	payload := []byte(`{"event":"test"}`)

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		tamperBody bool
		wantStatus int
	}{
		{"valid", func(r *http.Request) {}, false, http.StatusOK},
		{"missing signature", func(r *http.Request) {
			r.Header.Del("webhook-signature")
		}, false, http.StatusUnauthorized},
		{"missing timestamp", func(r *http.Request) {
			r.Header.Del("webhook-timestamp")
		}, false, http.StatusUnauthorized},
		{"expired timestamp", func(r *http.Request) {
			r.Header.Set("webhook-timestamp", "1000000000") // year 2001
		}, false, http.StatusUnauthorized},
		{"future timestamp", func(r *http.Request) {
			r.Header.Set("webhook-timestamp", "9999999999") // future
		}, false, http.StatusUnauthorized},
		{"tampered body", func(r *http.Request) {}, true, http.StatusUnauthorized},
		{"wrong signature prefix", func(r *http.Request) {
			r.Header.Set("webhook-signature", "v2,abc")
		}, false, http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			var err error

			if tc.tamperBody {
				resp, err = sender.SignAndSendTampered(srv.URL, testSecret, payload)
			} else {
				req, errReq := sender.NewRequest(srv.URL, testSecret, payload)
				if errReq != nil {
					t.Fatalf("failed to create request: %v", errReq)
				}
				tc.mutate(req)
				resp, err = http.DefaultClient.Do(req)
			}

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

func TestBodyRestored(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	var seen []byte

	handler := New(Config{Secret: testSecret}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = io.ReadAll(r.Body)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := sender.SignAndSend(srv.URL, testSecret, payload)
	if err != nil {
		t.Fatalf("failed to send: %v", err)
	}
	defer resp.Body.Close()

	if !bytes.Equal(seen, payload) {
		t.Errorf("handler saw %q, want %q", seen, payload)
	}
}

func TestConcurrentRequests(t *testing.T) {
	srv := httptest.NewServer(New(Config{Secret: testSecret}, okHandler()))
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := sender.SignAndSend(srv.URL, testSecret, []byte(`{}`))
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
}

func FuzzTimestamp(f *testing.F) {
	f.Add("1695000000")
	f.Add("abc")
	f.Add("")
	f.Add("-1")
	f.Add("999999999999999999999")

	f.Fuzz(func(t *testing.T, ts string) {
		_, err := strconv.ParseInt(ts, 10, 64)
		_ = err
	})
}
