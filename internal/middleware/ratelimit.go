package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// ipLimiter pairs a per-IP rate limiter with the last time it was accessed so
// idle entries can be evicted by Cleanup, preventing unbounded map growth.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter manages rate limiters per IP address
type IPRateLimiter struct {
	ips map[string]*ipLimiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*ipLimiter),
		mu:  &sync.RWMutex{},
		r:   r,
		b:   b,
	}
}

// AddIP creates a new rate limiter for an IP address
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips[ip] = &ipLimiter{limiter: limiter, lastSeen: time.Now()}

	return limiter
}

// GetLimiter returns the rate limiter for an IP address
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	entry, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	entry.lastSeen = time.Now()
	i.mu.Unlock()
	return entry.limiter
}

// Cleanup removes IP entries that have not been seen within maxAge. Call it
// periodically (see StartCleanup) so the per-IP map does not grow unbounded.
func (i *IPRateLimiter) Cleanup(maxAge time.Duration) {
	i.mu.Lock()
	defer i.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for ip, entry := range i.ips {
		if entry.lastSeen.Before(cutoff) {
			delete(i.ips, ip)
			removed++
		}
	}

	if removed > 0 {
		slog.Debug("Rate limiter cleanup evicted idle IP entries", "removed", removed, "remaining", len(i.ips))
	}
}

// StartCleanup launches a background goroutine that periodically evicts idle IP
// entries older than maxAge. It runs until stop is closed.
func (i *IPRateLimiter) StartCleanup(interval, maxAge time.Duration, stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				i.Cleanup(maxAge)
			case <-stop:
				slog.Debug("Rate limiter cleanup goroutine stopping")
				return
			}
		}
	}()
}

// RateLimitMiddleware creates a rate limiting middleware for Gin
func RateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		rl := limiter.GetLimiter(ip)

		if !rl.Allow() {
			slog.Warn("Rate limit exceeded", "ip", ip, "path", c.Request.URL.Path)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// AuthRateLimiter is a stricter rate limiter for authentication endpoints
func AuthRateLimiter() *IPRateLimiter {
	// Allow 5 requests per minute per IP for auth endpoints
	return NewIPRateLimiter(rate.Every(time.Minute/5), 5)
}

// APIRateLimiter is a moderate rate limiter for API endpoints
func APIRateLimiter() *IPRateLimiter {
	// Allow 60 requests per minute per IP for API endpoints
	return NewIPRateLimiter(rate.Every(time.Second), 60)
}
