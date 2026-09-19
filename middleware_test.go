package sallyport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/nehanz/sallyport/internal/idempotency"
	"github.com/nehanz/sallyport/internal/sender"
)

const testSecret = "whsec_test_secret"

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func newTestMiddleware(store idempotency.Store) http.Handler {
	return New(Config{Secret: testSecret, Idempotency: store}, okHandler())
}


func TestMiddleware(t *testing.T) {
	srv := httptest.NewServer(newTestMiddleware(idempotency.NewMemoryStore()))
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
			r.Header.Set("webhook-timestamp", "9999999999")
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
				req, reqErr := sender.NewRequest(srv.URL, testSecret, payload)
				if reqErr != nil {
					t.Fatalf("failed to create request: %v", reqErr)
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

	handler := New(Config{Secret: testSecret, Idempotency: idempotency.NewMemoryStore()},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	srv := httptest.NewServer(newTestMiddleware(idempotency.NewMemoryStore()))
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

func TestIdempotency(t *testing.T) {
	store := idempotency.NewMemoryStore()
	var handled atomic.Int32

	handler := New(Config{Secret: testSecret, Idempotency: store},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled.Add(1)
			w.WriteHeader(http.StatusOK)
		}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	payload := []byte(`{"event":"payment.succeeded"}`)
	req, err := sender.SignRequest(srv.URL, testSecret, payload)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	for i := 0; i < 2; i++ {
		r := req.Clone(context.Background())
		r.Body = io.NopCloser(bytes.NewReader(payload))
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatalf("send %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("send %d: got status %d, want 200", i, resp.StatusCode)
		}
	}

	if got := handled.Load(); got != 1 {
		t.Errorf("handler called %d times, want 1", got)
	}
}

func TestClaimReleasedOn5xx(t *testing.T) {
	store := idempotency.NewMemoryStore()
	var calls atomic.Int32

	handler := New(Config{Secret: testSecret, Idempotency: store},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if calls.Add(1) == 1 {
				http.Error(w, "temporary error", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	payload := []byte(`{"event":"payment.succeeded"}`)
	req, err := sender.SignRequest(srv.URL, testSecret, payload)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	r1 := req.Clone(context.Background())
	r1.Body = io.NopCloser(bytes.NewReader(payload))
	resp1, _ := http.DefaultClient.Do(r1)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusInternalServerError {
		t.Errorf("first send: got %d, want 500", resp1.StatusCode)
	}

	r2 := req.Clone(context.Background())
	r2.Body = io.NopCloser(bytes.NewReader(payload))
	resp2, _ := http.DefaultClient.Do(r2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second send: got %d, want 200", resp2.StatusCode)
	}

	if got := calls.Load(); got != 2 {
		t.Errorf("handler called %d times, want 2", got)
	}
}

func TestConcurrentDuplicates(t *testing.T) {
	store := idempotency.NewMemoryStore()
	var handled atomic.Int32

	handler := New(Config{Secret: testSecret, Idempotency: store},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled.Add(1)
			w.WriteHeader(http.StatusOK)
		}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	payload := []byte(`{}`)
	req, err := sender.SignRequest(srv.URL, testSecret, payload)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := req.Clone(context.Background())
			r.Body = io.NopCloser(bytes.NewReader(payload))
			resp, err := http.DefaultClient.Do(r)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	if got := handled.Load(); got != 1 {
		t.Errorf("handler called %d times, want exactly 1", got)
	}
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
