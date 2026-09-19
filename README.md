# Sallyport

Sallyport is a secure, lightweight Go HTTP middleware for webhook verification and replay protection following the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks) specification.

## Features

- **Signature Verification**: Validates HMAC-SHA256 signatures with constant-time equality checks.
- **Timestamp Freshness**: Rejects expired or future-dated webhook deliveries.
- **Idempotency & Deduplication**: Ensures each webhook is processed once (in-memory or persistent SQLite).
- **Auto-Retry Support**: Automatically releases claims on 5xx server errors so providers can retry.
- **Zero-Downtime Secret Rotation**: Supports multiple active secrets and multi-signature headers.
- **SSRF Protection**: Provides safe HTTP clients that block loopback, internal subnets, and cloud metadata endpoints.

---

## Installation

```bash
go get github.com/nehanz/sallyport
```

---

## Quickstart

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/nehanz/sallyport"
)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

func main() {
	middleware := sallyport.New(sallyport.Config{
		Secret: os.Getenv("WEBHOOK_SECRET"),
	}, http.HandlerFunc(webhookHandler))

	http.Handle("/webhooks", middleware)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Common Use Cases

### 1. Persistent Storage (SQLite)

Persist processed message IDs across server restarts:

```go
store, err := sallyport.NewSQLiteStore("./webhooks.db")
if err != nil {
	log.Fatal(err)
}

middleware := sallyport.New(sallyport.Config{
	Secret:      os.Getenv("WEBHOOK_SECRET"),
	Idempotency: store,
}, appHandler)
```

### 2. Secret Rotation

Rotate webhook signing secrets without downtime:

```go
middleware := sallyport.New(sallyport.Config{
	Secrets: []string{
		os.Getenv("NEW_WEBHOOK_SECRET"),
		os.Getenv("OLD_WEBHOOK_SECRET"),
	},
}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// Check which secret was matched
	matchedSecret := sallyport.MatchedSecret(r.Context())
	log.Printf("Verified with: %s", matchedSecret)
	w.WriteHeader(http.StatusOK)
}))
```

### 3. SSRF-Safe Outbound Client

If your application dispatches webhooks or calls external callback URLs:

```go
client := sallyport.NewSafeClient(10 * time.Second)

// Blocks 127.0.0.1, private IPs (10.x, 192.168.x), and cloud metadata (169.254.169.254)
resp, err := client.Get("https://example.com/webhook")
```

---

## Configuration Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `Secret` | `string` | `""` | Single active signing secret. |
| `Secrets` | `[]string` | `nil` | Multiple secrets for rotation (takes precedence). |
| `Tolerance` | `time.Duration` | `5m` | Maximum allowed timestamp drift. |
| `Idempotency` | `sallyport.Store` | `MemoryStore` | Store backend (`NewMemoryStore` or `NewSQLiteStore`). |
| `ClaimTTL` | `time.Duration` | `24h` | Time to remember processed message IDs. |
