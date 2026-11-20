package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("could not load .env")
	}
	if err := InitAuth(); err != nil {
		return err
	}
	if err := InitDB(); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer CloseDB()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", RegisterHandler)
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/profile", AuthMiddleware(ProfileHandler))
	mux.HandleFunc("/health", HealthHandler)

	address := net.JoinHostPort("127.0.0.1", getEnv("SERVER_PORT", "8080"))
	log.Printf("Server listening on http://%s", address)
	return http.ListenAndServe(address, mux)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
