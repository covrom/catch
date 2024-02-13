package catch

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type StringLimiter struct {
	Key     string
	Limiter *rate.Limiter
}

type KeyRateLimiter struct {
	keys []StringLimiter
	mu   *sync.RWMutex
	r    rate.Limit
	b    int
}

func NewKeyRateLimiter(r rate.Limit, b int) *KeyRateLimiter {
	i := &KeyRateLimiter{
		keys: make([]StringLimiter, 0, 100),
		mu:   &sync.RWMutex{},
		r:    r,
		b:    b,
	}

	go i.cleaner()

	return i
}

func (i *KeyRateLimiter) cleaner() {
	tck := time.NewTicker(time.Second)
	for range tck.C {
		i.mu.Lock()
		if len(i.keys) > 0 {
			i.keys = i.keys[:len(i.keys)-1]
		}
		i.mu.Unlock()
	}
}

func (i *KeyRateLimiter) addKeyLimiter(key string) *rate.Limiter {
	limiter := rate.NewLimiter(i.r, i.b)

	ilim := StringLimiter{
		Key:     key,
		Limiter: limiter,
	}

	if len(i.keys) < 100 {
		i.keys = append(i.keys, StringLimiter{})
	}
	copy(i.keys[1:], i.keys[0:])
	i.keys[0] = ilim

	return limiter
}

func (i *KeyRateLimiter) GetKeyLimiter(key string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, limiter := range i.keys {
		if limiter.Key == key {
			return limiter.Limiter
		}
	}
	return i.addKeyLimiter(key)
}

func LimitIPMiddleware(limiter *KeyRateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limiter := limiter.GetKeyLimiter(r.RemoteAddr)
			if !limiter.Allow() {
				http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
