package sallyport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

func TestSecretRotation(t *testing.T) {
	primarySecret := "whsec_new_active_secret"
	oldSecret := "whsec_old_retiring_secret"
	unknownSecret := "whsec_unknown_evil_secret"

	var lastMatchedSecret string
	var mu sync.Mutex

	handler := New(Config{
		Secrets:     []string{primarySecret, oldSecret},
		Idempotency: idempotency.NewMemoryStore(),
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastMatchedSecret = MatchedSecret(r.Context())
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	payload := []byte(`{"event":"user.created"}`)

	resp, err := sender.SignAndSend(srv.URL, primarySecret, payload)
	if err != nil {
		t.Fatalf("send with primary secret failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("primary secret: got %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	if lastMatchedSecret != primarySecret {
		t.Errorf("expected matched secret %q, got %q", primarySecret, lastMatchedSecret)
	}
	mu.Unlock()

	resp, err = sender.SignAndSend(srv.URL, oldSecret, payload)
	if err != nil {
		t.Fatalf("send with old secret failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("old secret: got %d, want 200", resp.StatusCode)
	}
	mu.Lock()
	if lastMatchedSecret != oldSecret {
		t.Errorf("expected matched secret %q, got %q", oldSecret, lastMatchedSecret)
	}
	mu.Unlock()

	reqMulti, _ := sender.NewRequest(srv.URL, primarySecret, payload)
	msgID := reqMulti.Header.Get("webhook-id")
	ts := reqMulti.Header.Get("webhook-timestamp")
	sigPrimary := reqMulti.Header.Get("webhook-signature")

	mac := hmac.New(sha256.New, []byte(oldSecret))
	mac.Write([]byte(msgID + "." + ts + "." + string(payload)))
	sigOld := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	reqMulti.Header.Set("webhook-signature", sigPrimary+" "+sigOld)

	resp, err = http.DefaultClient.Do(reqMulti)
	if err != nil {
		t.Fatalf("send with multi-signature header failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("multi-signature header: got %d, want 200", resp.StatusCode)
	}

	resp, err = sender.SignAndSend(srv.URL, unknownSecret, payload)
	if err != nil {
		t.Fatalf("send with unknown secret failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown secret: got %d, want 401", resp.StatusCode)
	}
}

func TestSQLiteMiddlewareIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "middleware_claims.db")

	store, err := idempotency.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	var handled atomic.Int32
	handler := New(Config{
		Secret:      testSecret,
		Idempotency: store,
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	srv := httptest.NewServer(handler)
	defer srv.Close()

	payload := []byte(`{"event":"order.completed"}`)
	req, err := sender.SignRequest(srv.URL, testSecret, payload)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	r1 := req.Clone(context.Background())
	r1.Body = io.NopCloser(bytes.NewReader(payload))
	resp1, err := http.DefaultClient.Do(r1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Errorf("first request: got status %d, want 200", resp1.StatusCode)
	}

	r2 := req.Clone(context.Background())
	r2.Body = io.NopCloser(bytes.NewReader(payload))
	resp2, err := http.DefaultClient.Do(r2)
	if err != nil {
		t.Fatalf("replay request failed: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("replay request: got status %d, want 200", resp2.StatusCode)
	}

	if got := handled.Load(); got != 1 {
		t.Errorf("handler called %d times, want 1", got)
	}
}

