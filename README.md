# Sallyport

Sallyport is a secure, production-ready Go HTTP middleware for validating webhook signatures. It implements the [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks) specification to protect your API endpoints from unauthorized access and replay attacks.

## What It Protects Against

1. **Forgery Attacks**: Ensures the request was actually sent by the trusted party who holds the shared secret key, not a malicious actor.
2. **Replay Attacks**: Uses a timestamp and message ID included in the signature to ensure that intercepted payloads cannot be re-sent later. 
3. **Timing Attacks**: Uses constant-time string comparison (`hmac.Equal`) to prevent attackers from guessing the signature character-by-character based on response times.

## How it Works

The middleware expects the following headers to be present in incoming webhook requests:
- `webhook-id`: A unique identifier for the message.
- `webhook-timestamp`: The Unix timestamp when the request was signed.
- `webhook-signature`: A base64-encoded HMAC-SHA256 hash.

It constructs a signed string in the format `msg_id.timestamp.raw_body` and hashes it using your configured secret. If the hashes match and the timestamp is within the allowed tolerance window (default 5 minutes), the request is passed to your application.

## Usage

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/nehanz/sallyport"
)

func main() {
	secret := os.Getenv("WEBHOOK_SECRET")
	
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Webhook processed successfully!")
		w.WriteHeader(http.StatusOK)
	})

    // Wrap your handler with the sallyport middleware
	http.Handle("/webhook", sallyport.New(sallyport.Config{Secret: secret}, appHandler))
	
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
