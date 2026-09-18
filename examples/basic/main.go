package main

import (
    "log"
    "net/http"
    "os"

    "github.com/nehanz/sallyport/internal/receiver"
)

func main() {
    secret := os.Getenv("WEBHOOK_SECRET")
    if secret == "" {
        log.Fatal("WEBHOOK_SECRET environment variable is required. Have you loaded the .env file?")
    }
    
    http.Handle("/webhook", receiver.Handler(secret))
    log.Println("listening on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
