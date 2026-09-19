package main

import (
	"log"
	"net/http"
	"os"

	"github.com/nehanz/sallyport"
)

func main() {
	secret := os.Getenv("WEBHOOK_SECRET")
	if secret == "" {
		log.Fatal("WEBHOOK_SECRET environment variable is required")
	}

	store := sallyport.NewMemoryStore()

	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("Webhook processed successfully!")
		w.WriteHeader(http.StatusOK)
	})

	http.Handle("/webhook", sallyport.New(sallyport.Config{
		Secret:      secret,
		Idempotency: store,
	}, appHandler))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
