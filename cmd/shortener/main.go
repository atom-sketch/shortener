package main

import (
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"shortener/internal/app"
)

func main() {
	const addr = ":8080"
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		log.Fatalf("generate cookie signing key: %v", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           app.New("http://localhost"+addr, secret[:]),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       time.Minute,
	}
	log.Printf("URL shortener listening on http://localhost%s", addr)
	log.Fatal(server.ListenAndServe())
}
