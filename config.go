package guardian

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/jwt"
	"github.com/simp-lee/guardian/middleware"
	"github.com/simp-lee/guardian/storage"
)

// Config holds the core configuration for Guardian.
type Config struct {
	SecretKey       string
	Storage         storage.Storage
	CleanupInterval time.Duration // For both JWT and RateLimit cleanup

	HeaderName string
	TokenType  string

	RefreshThreshold  time.Duration
	EnableAutoRefresh bool
}

// DefaultConfig returns a configuration with reasonable defaults.
func DefaultConfig() Config {
	return Config{
		HeaderName:        "Authorization",
		TokenType:         "Bearer",
		CleanupInterval:   1 * time.Hour,
		RefreshThreshold:  5 * time.Minute,
		EnableAutoRefresh: false,
	}
}

type Option func(*Config)

// WithSecretKey sets the secret key used for JWT token signing.
func WithSecretKey(key string) Option {
	return func(c *Config) {
		c.SecretKey = key
	}
}

// WithStorage sets a custom storage implementation.
func WithStorage(storage storage.Storage) Option {
	return func(c *Config) {
		c.Storage = storage
	}
}

// WithHeaderName sets the HTTP header name used for authentication.
func WithHeaderName(name string) Option {
	return func(c *Config) {
		c.HeaderName = name
	}
}

// WithTokenType sets the token type (e.g., "Bearer").
func WithTokenType(tokenType string) Option {
	return func(c *Config) {
		c.TokenType = tokenType
	}
}

// WithCleanupInterval sets how often revoked tokens and rate limit entries are cleaned up.
// This is a global setting for both JWT and RateLimit middleware.
func WithCleanupInterval(interval time.Duration) Option {
	return func(c *Config) {
		c.CleanupInterval = interval
	}
}

// WithAutoRefresh enables and configures automatic token refresh.
func WithAutoRefresh(threshold time.Duration) Option {
	return func(c *Config) {
		c.RefreshThreshold = threshold
		c.EnableAutoRefresh = true
	}
}

// ---------------------------------------------------------------------------
// Auth Middleware Options
// ---------------------------------------------------------------------------

type AuthOption func(*middleware.AuthOptions)

func WithAuthHeaderName(name string) AuthOption {
	return func(o *middleware.AuthOptions) {
		o.HeaderName = name
	}
}

func WithAuthTokenType(tokenType string) AuthOption {
	return func(o *middleware.AuthOptions) {
		o.TokenType = tokenType
	}
}

func OnAuthSuccess(fn func(*gin.Context, *jwt.Token)) AuthOption {
	return func(o *middleware.AuthOptions) {
		o.OnSuccess = fn
	}
}

func OnAuthFailure(fn func(*gin.Context, error)) AuthOption {
	return func(o *middleware.AuthOptions) {
		o.OnFailure = fn
	}
}

func WithAuthErrorHandler(fn func(*gin.Context, error)) AuthOption {
	return func(o *middleware.AuthOptions) {
		o.ErrorHandler = fn
	}
}

// ----------------------------------------------------------------------------
// Auto Refresh Middleware Options
// ----------------------------------------------------------------------------

type AutoRefreshOption func(*middleware.AutoRefreshOptions)

func OnTokenRefresh(fn func(*gin.Context, string, string)) AutoRefreshOption {
	return func(o *middleware.AutoRefreshOptions) {
		o.OnRefresh = fn
	}
}

func WithRefreshThreshold(threshold time.Duration) AutoRefreshOption {
	return func(o *middleware.AutoRefreshOptions) {
		o.RefreshThreshold = threshold
	}
}

// ----------------------------------------------------------------------------
// Permission Middleware Options
// ----------------------------------------------------------------------------

type PermissionOption func(*middleware.PermissionOptions)

func OnPermissionGranted(fn func(*gin.Context, string, string, string)) PermissionOption {
	return func(o *middleware.PermissionOptions) {
		o.OnGranted = fn
	}
}

func OnPermissionDenied(fn func(*gin.Context, string, string, string)) PermissionOption {
	return func(o *middleware.PermissionOptions) {
		o.OnDenied = fn
	}
}

func WithPermissionErrorHandler(fn func(*gin.Context, error)) PermissionOption {
	return func(o *middleware.PermissionOptions) {
		o.ErrorHandler = fn
	}
}

// ----------------------------------------------------------------------------
// Role Middleware Options
// ----------------------------------------------------------------------------

type RoleOption func(*middleware.RoleOptions)

func OnRoleGranted(fn func(*gin.Context, string, []string)) RoleOption {
	return func(o *middleware.RoleOptions) {
		o.OnGranted = fn
	}
}

func OnRoleDenied(fn func(*gin.Context, string, []string)) RoleOption {
	return func(o *middleware.RoleOptions) {
		o.OnDenied = fn
	}
}

func WithRoleErrorHandler(fn func(*gin.Context, error)) RoleOption {
	return func(o *middleware.RoleOptions) {
		o.ErrorHandler = fn
	}
}

// ----------------------------------------------------------------------------
// Rate Limit Middleware Options
// ----------------------------------------------------------------------------

type RateLimitOption func(*middleware.RateLimitOptions)

func WithRateLimitRequestsPerMinute(rpm int) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.RequestsPerMinute = rpm
	}
}

func WithRateLimitBurst(maxBurst int) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.Burst = maxBurst
	}
}

func WithRateLimitCleanupInterval(interval time.Duration) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.CleanupInterval = interval
	}
}

func WithRateLimitExpirationTime(expiration time.Duration) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.ExpirationTime = expiration
	}
}

func WithRateLimitErrorHandler(fn func(*gin.Context, error)) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.ErrorHandler = fn
	}
}

func WithRateLimitKeyExtractor(fn func(*gin.Context) string) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.KeyExtractor = fn
	}
}

func OnRateLimited(fn func(string, *gin.Context)) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.OnRateLimited = fn
	}
}

func OnRateLimitRequest(fn func(string, int, *gin.Context)) RateLimitOption {
	return func(o *middleware.RateLimitOptions) {
		o.OnRequest = fn
	}
}
