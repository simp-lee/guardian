package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// RateLimitOptions defines configuration options for the rate limit middleware.
type RateLimitOptions struct {
	RequestsPerMinute int // RequestsPerMinute is the maximum number of requests allowed per minute, default 60
	Burst             int // Burst is the number of requests allowed to exceed the rate limit, default equal to RequestsPerMinute
	CleanupInterval   time.Duration
	ExpirationTime    time.Duration // ExpirationTime is the duration after which an entry is considered expired, default 10 minutes
	ErrorHandler      func(*gin.Context, error)
	KeyExtractor      func(*gin.Context) string                       // KeyExtractor is a function that extracts the key from the request, default uses the client IP address
	OnRateLimited     func(key string, c *gin.Context)                // OnRateLimited is a function that is called when a request is rate limited
	OnRequest         func(key string, remaining int, c *gin.Context) // OnRequest is a function that is called when a request is made
}

// DefaultRateLimitOptions returns the default options for the rate limit middleware.
func DefaultRateLimitOptions() RateLimitOptions {
	return RateLimitOptions{
		RequestsPerMinute: 60,
		Burst:             60,
		CleanupInterval:   5 * time.Minute,
		ExpirationTime:    10 * time.Minute,
		KeyExtractor:      func(c *gin.Context) string { return c.ClientIP() },
		OnRateLimited:     func(string, *gin.Context) {},
		OnRequest:         func(string, int, *gin.Context) {},
		ErrorHandler:      DefaultRateLimitErrorHandler,
	}
}

// RateLimit limits the number of requests per minute from a single IP address.
// It returns both the middleware handler and a cleanup function that should be called when
// the server shuts down.
func RateLimit(opts RateLimitOptions) (gin.HandlerFunc, func()) {
	requestsPerMinute := opts.RequestsPerMinute
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}

	burst := opts.Burst
	if burst <= 0 {
		burst = requestsPerMinute
	}

	cleanupInterval := opts.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = 5 * time.Minute
	}

	expirationTime := opts.ExpirationTime
	if expirationTime <= 0 {
		expirationTime = 10 * time.Minute
	}

	handleError := opts.ErrorHandler
	if handleError == nil {
		handleError = DefaultRateLimitErrorHandler
	}

	// Use the client IP address as the default key extractor
	keyExtractor := opts.KeyExtractor
	if keyExtractor == nil {
		keyExtractor = func(c *gin.Context) string {
			return c.ClientIP()
		}
	}

	onRateLimited := opts.OnRateLimited
	if onRateLimited == nil {
		onRateLimited = func(key string, c *gin.Context) {}
	}

	onRequest := opts.OnRequest
	if onRequest == nil {
		onRequest = func(key string, remaining int, c *gin.Context) {}
	}

	limiters := &sync.Map{}
	ctx, cancel := context.WithCancel(context.Background())

	// Start a goroutine to clean up expired entries
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				now := time.Now()
				limiters.Range(func(key, value any) bool {
					limiterData := value.(*rateLimiterData)

					limiterData.mu.Lock()
					lastAccess := limiterData.lastAccess
					limiterData.mu.Unlock()

					// Delete the entry if it hasn't been accessed in the last 10 minutes
					if now.Sub(lastAccess) > expirationTime {
						limiters.Delete(key)
					}
					return true
				})
			case <-ctx.Done():
				return
			}
		}
	}()

	// Return the middleware handler and cleanup function
	return func(c *gin.Context) {
		key := keyExtractor(c)
		now := time.Now()

		// Get or create rate limit data for this IP
		limiterValue, _ := limiters.LoadOrStore(key, &rateLimiterData{
			limiter:    rate.NewLimiter(rate.Limit(requestsPerMinute)/60, burst),
			lastAccess: now,
		})

		limiterData := limiterValue.(*rateLimiterData)

		limiterData.mu.Lock()
		limiterData.lastAccess = now
		limiterData.mu.Unlock()

		limiter := limiterData.limiter
		if !limiter.Allow() {
			onRateLimited(key, c)
			handleError(c, ErrTooManyRequests)
			return
		}

		tokens := int(limiter.Tokens())
		remaining := 0
		if tokens < burst {
			remaining = tokens
		}

		onRequest(key, remaining, c)

		// Set rate limit headers
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", requestsPerMinute))

		c.Next()
	}, cancel
}

// rateLimiterData stores the rate limiter and last access time for a specific key.
type rateLimiterData struct {
	limiter    *rate.Limiter
	lastAccess time.Time
	mu         sync.RWMutex
}
