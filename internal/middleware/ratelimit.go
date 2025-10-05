package middleware

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// IPRateLimiter manages rate limiters per IP address
type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

// NewIPRateLimiter creates a new IP-based rate limiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
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
	i.ips[ip] = limiter

	return limiter
}

// GetLimiter returns the rate limiter for an IP address
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	i.mu.Unlock()
	return limiter
}

// Cleanup removes old IP entries (call periodically)
func (i *IPRateLimiter) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()

	// In production, you'd want to track last access time and remove old entries
	// For now, we keep all entries (memory leak potential in high-traffic scenarios)
	// TODO: Implement proper cleanup based on last access time
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
