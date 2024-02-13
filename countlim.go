package catch

import (
	"sync"
	"time"
)

type UniqueKeyLimiter struct {
	Key   string
	Count []string // unique keys for counting
}

type KeyCountLimiter struct {
	keys []UniqueKeyLimiter
	mu   *sync.RWMutex
	b    int // per second
}

func NewKeyCountLimiter(b int) *KeyCountLimiter {
	i := &KeyCountLimiter{
		keys: make([]UniqueKeyLimiter, 0, 100),
		mu:   &sync.RWMutex{},
		b:    b,
	}

	go i.cleaner()

	return i
}

func (i *KeyCountLimiter) cleaner() {
	tck := time.NewTicker(time.Second)
	for range tck.C {
		i.mu.Lock()
		for idx := len(i.keys) - 1; idx >= 0; idx-- {
			v := i.keys[idx]
			cnt := len(v.Count)
			if cnt <= i.b {
				i.keys = append(i.keys[:idx], i.keys[idx+1:]...)
			} else {
				cnt -= i.b
				v.Count = v.Count[:cnt]
				i.keys[idx] = v
			}
		}
		i.mu.Unlock()
	}
}

func (i *KeyCountLimiter) addKeyLimiter(key, countKey string) {
	ilim := UniqueKeyLimiter{
		Key:   key,
		Count: make([]string, 0, i.b*60),
	}
	ilim.Count = append(ilim.Count, countKey)

	if len(i.keys) < 100 {
		i.keys = append(i.keys, UniqueKeyLimiter{})
	}
	copy(i.keys[1:], i.keys[0:])
	i.keys[0] = ilim
}

func (i *KeyCountLimiter) Allow(key, countKey string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	for lidx := range i.keys {
		limiter := i.keys[lidx]
		if limiter.Key == key {
			fnd := false
			for _, v := range limiter.Count {
				if v == countKey {
					fnd = true

					break
				}
			}
			if !fnd {
				if len(limiter.Count) < i.b*60 {
					limiter.Count = append(limiter.Count, "")
				}
				copy(limiter.Count[1:], limiter.Count[0:])
				limiter.Count[0] = countKey
			}
			i.keys[lidx] = limiter

			return len(limiter.Count) > 0
		}
	}
	i.addKeyLimiter(key, countKey)
	return true
}
