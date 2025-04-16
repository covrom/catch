package catch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// RateLimiterConfig contains configuration for the rate limiter
type RateLimiterConfig struct {
	UserRequestsPerSecond   float64       // Requests per second limit per user
	UserBurst               int           // Maximum burst requests allowed per user
	GlobalRequestsPerSecond float64       // Global requests per second limit
	GlobalBurst             int           // Global burst limit
	CookieName              string        // Cookie name for user identification
	CookieMaxAge            int           // Cookie lifetime in seconds
	CleanupInterval         time.Duration // Interval for cleaning up unused data
	EncryptionKey           []byte        // Encryption key (32 bytes for AES-256)
}

// RateLimiter implements a middleware for request rate limiting
type RateLimiter struct {
	config        *RateLimiterConfig
	globalLimiter *TokenBucket
	userLimiters  map[string]*TokenBucket
	blockedUsers  map[string]time.Time
	mu            sync.Mutex
	stopChan      chan struct{}
	wg            sync.WaitGroup
	aead          cipher.AEAD
}

// TokenBucket implements the token bucket algorithm for rate limiting
type TokenBucket struct {
	capacity   int        // Bucket capacity
	tokens     int        // Current number of tokens
	refillRate float64    // Refill rate (tokens per second)
	lastRefill time.Time  // Time of last refill
	mu         sync.Mutex // Mutex for thread safety
}

// NewRateLimiter creates a new RateLimiter instance
func NewRateLimiter(config *RateLimiterConfig) (*RateLimiter, error) {
	if config == nil {
		config = &RateLimiterConfig{
			UserRequestsPerSecond:   10.0,
			UserBurst:               20,
			GlobalRequestsPerSecond: 100.0,
			GlobalBurst:             200,
			CookieName:              "ratelimit_token",
			CookieMaxAge:            3600 * 24,
			CleanupInterval:         5 * time.Minute,
		}
	}

	if len(config.EncryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes long for AES-256")
	}

	block, err := aes.NewCipher(config.EncryptionKey)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	rl := &RateLimiter{
		config:        config,
		globalLimiter: NewTokenBucket(config.GlobalRequestsPerSecond, config.GlobalBurst),
		userLimiters:  make(map[string]*TokenBucket),
		blockedUsers:  make(map[string]time.Time),
		stopChan:      make(chan struct{}),
		aead:          aead,
	}

	rl.wg.Add(1)
	go rl.cleanupWorker()

	return rl, nil
}

// Stop terminates background processes of the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	rl.wg.Wait()
}

// cleanupWorker performs periodic cleanup of unused data
func (rl *RateLimiter) cleanupWorker() {
	defer rl.wg.Done()

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanupMaps()
		case <-rl.stopChan:
			rl.cleanupMaps() // Final cleanup before exit
			return
		}
	}
}

// cleanupMaps recreates maps to prevent them from growing indefinitely
func (rl *RateLimiter) cleanupMaps() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Clean up userLimiters
	newUserLimiters := make(map[string]*TokenBucket)
	for userID, limiter := range rl.userLimiters {
		limiter.mu.Lock()
		lastRefill := limiter.lastRefill
		limiter.mu.Unlock()

		if time.Since(lastRefill) < 2*rl.config.CleanupInterval {
			newUserLimiters[userID] = limiter
		}
	}
	rl.userLimiters = newUserLimiters

	// Clean up blockedUsers
	newBlockedUsers := make(map[string]time.Time)
	now := time.Now()
	for userID, blockedUntil := range rl.blockedUsers {
		if blockedUntil.After(now) {
			newBlockedUsers[userID] = blockedUntil
		}
	}
	rl.blockedUsers = newBlockedUsers
}

// NewTokenBucket creates a new token bucket instance
func NewTokenBucket(rate float64, capacity int) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: rate,
		lastRefill: time.Now(),
	}
}

// Take attempts to take a token from the bucket
func (tb *TokenBucket) Take() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tokensToAdd := int(elapsed * tb.refillRate)

	if tokensToAdd > 0 {
		tb.tokens = min(tb.tokens+tokensToAdd, tb.capacity)
		tb.lastRefill = now
	}

	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// Middleware returns a middleware function for request rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Check global limit
		if !rl.globalLimiter.Take() {
			http.Error(w, "Server too busy", http.StatusTooManyRequests)
			return
		}

		// 2. Get user identifier
		userID := rl.getUserIdentifier(r)

		// 3. Check if user is blocked
		if blockedUntil, ok := rl.isUserBlocked(userID); ok {
			w.Header().Set("Retry-After", blockedUntil.Format(time.RFC1123))
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// 4. Get or create limiter for user
		userLimiter := rl.getUserLimiter(userID)

		// 5. Check user limit
		if !userLimiter.Take() {
			rl.blockUser(userID)
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// 6. Set cookie if not present
		rl.setUserCookie(w, userID)

		// Pass control to the next handler
		next.ServeHTTP(w, r)
	})
}

// encryptUserID encrypts user identifier
func (rl *RateLimiter) encryptUserID(userID string) (string, error) {
	nonce := make([]byte, rl.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	encrypted := rl.aead.Seal(nonce, nonce, []byte(userID), nil)
	return base64.URLEncoding.EncodeToString(encrypted), nil
}

// decryptUserID decrypts user identifier
func (rl *RateLimiter) decryptUserID(encrypted string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	if len(decoded) < rl.aead.NonceSize() {
		return "", errors.New("invalid encrypted data")
	}

	nonce := decoded[:rl.aead.NonceSize()]
	ciphertext := decoded[rl.aead.NonceSize():]

	plaintext, err := rl.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// getUserIdentifier returns the user identifier
func (rl *RateLimiter) getUserIdentifier(r *http.Request) string {
	cookie, err := r.Cookie(rl.config.CookieName)
	if err != nil {
		return r.RemoteAddr
	}

	userID, err := rl.decryptUserID(cookie.Value)
	if err != nil {
		return r.RemoteAddr
	}

	return userID
}

// isUserBlocked checks if user is blocked
func (rl *RateLimiter) isUserBlocked(userID string) (time.Time, bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	blockedUntil, ok := rl.blockedUsers[userID]
	if !ok {
		return time.Time{}, false
	}

	if time.Now().After(blockedUntil) {
		delete(rl.blockedUsers, userID)
		return time.Time{}, false
	}

	return blockedUntil, true
}

// blockUser blocks user for 1 minute
func (rl *RateLimiter) blockUser(userID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.blockedUsers[userID] = time.Now().Add(time.Minute)
}

// getUserLimiter returns limiter for user
func (rl *RateLimiter) getUserLimiter(userID string) *TokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, ok := rl.userLimiters[userID]; ok {
		return limiter
	}

	limiter := NewTokenBucket(rl.config.UserRequestsPerSecond, rl.config.UserBurst)
	rl.userLimiters[userID] = limiter
	return limiter
}

// setUserCookie sets encrypted cookie for user
func (rl *RateLimiter) setUserCookie(w http.ResponseWriter, userID string) {
	encryptedID, err := rl.encryptUserID(userID)
	if err != nil {
		slog.Error("rl.encryptUserID error", "err", err, "userID", userID)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     rl.config.CookieName,
		Value:    encryptedID,
		MaxAge:   rl.config.CookieMaxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
