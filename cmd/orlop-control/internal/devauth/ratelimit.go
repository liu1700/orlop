package devauth

import (
	"sync"
	"time"
)

// RateLimiter is a per-key token bucket. Buckets refill at rate/window
// and cap at rate. Used to bound device-code creation, approval
// attempts, and token polling per IP. Constructed by callers with the
// limit appropriate for the route.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    int
	window  time.Duration
	now     func() time.Time
}

type bucket struct {
	tokens int
	last   time.Time
}

// NewRateLimiter allows up to rate requests per window per key.
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		window:  window,
		now:     func() time.Time { return time.Now() },
	}
}

// Allow returns true if the key may proceed and consumes one token.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	b, ok := r.buckets[key]
	if !ok {
		r.buckets[key] = &bucket{tokens: r.rate - 1, last: now}
		return true
	}
	per := r.window / time.Duration(r.rate)
	if per > 0 {
		if refill := int(now.Sub(b.last) / per); refill > 0 {
			b.tokens += refill
			if b.tokens > r.rate {
				b.tokens = r.rate
			}
			b.last = b.last.Add(time.Duration(refill) * per)
		}
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}
