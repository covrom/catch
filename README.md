Catch - Go Middleware Package
The catch package provides a collection of HTTP middleware and utilities for Go applications, including request forwarding, panic recovery, security headers, structured logging, rate limiting, and RSA encryption. This README provides instructions for installing, configuring, and using the package.
Features

Request Forwarding Middleware: Updates request host, protocol, and client IP based on forwarded headers (X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-For, etc.).
Panic Recovery Middleware: Recovers from panics, logs stack traces, and returns a structured error response.
Security Headers Middleware: Adds HTTP security headers like Strict-Transport-Security, X-XSS-Protection, and X-Content-Type-Options.
Structured Logging Middleware: Logs HTTP requests with customizable fields using slog, supporting request IDs, headers, and performance metrics.
Rate Limiting Middleware: Implements token bucket-based rate limiting for both global and per-user requests, with encrypted user identification via cookies.
RSA Cryptography Utilities: Provides functions for generating RSA key pairs, encrypting/decrypting messages, and signing/verifying signatures.

Prerequisites

Go: Version 1.18 or higher.
Dependencies: The package uses external libraries, which will be installed automatically via go get.

Installation

Clone the Repository (if you are contributing or want the source code directly):
git clone https://github.com/yourusername/catch.git
cd catch


Install the Package (if you are using it as a dependency):Add the package to your Go project by running:
go get github.com/yourusername/catch


Install Dependencies:The package relies on the following external libraries, which will be fetched automatically when you build or run your project:

github.com/go-chi/chi/v5
github.com/go-chi/renderEnsure your go.mod file includes these dependencies, or run:

go mod tidy


Verify Installation:Create a simple Go program to test the package import:
package main

import (
    "github.com/yourusername/catch"
    "net/http"
)

func main() {
    http.ListenAndServe(":8080", catch.Recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Hello, World!"))
    })))
}

Run the program:
go run main.go

Visit http://localhost:8080 to verify the server is running.


Usage
Below are examples of how to use each component of the catch package in a Go HTTP server.
1. Request Forwarding Middleware
The RequestForwardedHostProtoMiddleware updates the request's host, protocol, and client IP based on forwarded headers, useful for applications behind proxies.
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/catch"
    "net/http"
)

func main() {
    r := chi.NewRouter()
    r.Use(catch.RequestForwardedHostProtoMiddleware)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Host: " + r.Host + ", Proto: " + r.URL.Scheme + ", RemoteAddr: " + r.RemoteAddr))
    })
    http.ListenAndServe(":8080", r)
}

2. Panic Recovery Middleware
The Recoverer middleware catches panics, logs them, and returns a 500 Internal Server Error response.
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/catch"
    "net/http"
)

func main() {
    r := chi.NewRouter()
    r.Use(catch.Recoverer)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        panic("Something went wrong!")
    })
    http.ListenAndServe(":8080", r)
}

3. Security Headers Middleware
The Protection middleware adds security headers to responses.
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/catch"
    "net/http"
)

func main() {
    r := chi.NewRouter()
    r.Use(catch.Protection)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Secure response"))
    })
    http.ListenAndServe(":8080", r)
}

4. Structured Logging Middleware
The NewStructuredLogger middleware logs HTTP requests with structured fields using slog.
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/catch"
    "log/slog"
    "net/http"
    "os"
)

func main() {
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    slog.SetDefault(logger)
    r := chi.NewRouter()
    r.Use(catch.NewStructuredLogger(logger.Handler(), false)) // Log all requests
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        catch.LogEntrySetField(r, "custom_field", "value")
        w.Write([]byte("Logged request"))
    })
    http.ListenAndServe(":8080", r)
}

5. Rate Limiting Middleware
The RateLimiter middleware enforces request limits per user and globally, using encrypted cookies for user identification.
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/yourusername/catch"
    "net/http"
)

func main() {
    config := &catch.RateLimiterConfig{
        UserRequestsPerSecond:   5.0,
        UserBurst:               10,
        GlobalRequestsPerSecond: 50.0,
        GlobalBurst:             100,
        CookieName:              "ratelimit_token",
        CookieMaxAge:            3600 * 24,
        CleanupInterval:         5 * time.Minute,
        EncryptionKey:           []byte("32-byte-long-key-1234567890123456"), // Must be 32 bytes
    }
    rl, err := catch.NewRateLimiter(config)
    if err != nil {
        panic(err)
    }
    defer rl.Stop()

    r := chi.NewRouter()
    r.Use(rl.Middleware)
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Rate-limited endpoint"))
    })
    http.ListenAndServe(":8080", r)
}

6. RSA Cryptography Utilities
The rsacrypt utilities provide RSA key generation, encryption/decryption, and signing/verification.
package main

import (
    "fmt"
    "github.com/yourusername/catch"
)

func main() {
    // Generate RSA key pair
    priv, pub, err := catch.GenerateKeyPair(2048)
    if err != nil {
        panic(err)
    }

    // Encrypt a message
    msg := []byte("Secret message")
    ciphertext, err := catch.EncryptWithPublicKey(msg, pub)
    if err != nil {
        panic(err)
    }

    // Decrypt the message
    plaintext, err := catch.DecryptWithPrivateKey(ciphertext, priv)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decrypted: %s\n", plaintext)

    // Sign a message
    signature, err := catch.SignWithPrivateKey(msg, priv)
    if err != nil {
        panic(err)
    }

    // Verify the signature
    err = catch.VerifyWithPublicKey(msg, signature, pub)
    if err == nil {
        fmt.Println("Signature verified")
    } else {
        fmt.Println("Signature verification failed")
    }
}

Configuration
Rate Limiter Configuration
The RateLimiterConfig struct allows customization of the rate limiter:
config := &catch.RateLimiterConfig{
    UserRequestsPerSecond:   10.0,           // 10 requests per second per user
    UserBurst:               20,             // Allow bursts up to 20 requests
    GlobalRequestsPerSecond: 100.0,          // 100 requests per second globally
    GlobalBurst:             200,            // Allow global bursts up to 200
    CookieName:              "ratelimit_token", // Cookie name for user tracking
    CookieMaxAge:            3600 * 24,      // Cookie lifetime (1 day)
    CleanupInterval:         5 * time.Minute, // Cleanup unused data every 5 minutes
    EncryptionKey:           []byte("32-byte-long-key-1234567890123456"), // 32-byte AES-256 key
}

Structured Logger Configuration
The NewStructuredLogger function accepts a slog.Handler and a boolean to log only errors:
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
middleware := catch.NewStructuredLogger(logger.Handler(), true) // Log only errors

Building and Running

Build the Application:
go build -o myapp


Run the Application:
./myapp


Run Tests (if you have written tests):
go test ./...



Contributing

Fork the repository.
Create a new branch:git checkout -b feature/your-feature


Make your changes and commit:git commit -m "Add your feature"


Push to your fork:git push origin feature/your-feature


Create a pull request on GitHub.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Support
For issues or questions, open an issue on the GitHub repository or contact the maintainers at [your contact email].
