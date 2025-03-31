package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/jwt"
)

// AutoRefreshOptions defines configuration options for the auto-refresh middleware.
type AutoRefreshOptions struct {
	TokenService     jwt.Service
	HeaderName       string
	TokenType        string
	RefreshThreshold time.Duration
	OnRefresh        func(c *gin.Context, oldToken, newToken string)
}

// DefaultAutoRefreshOptions returns the default options for the auto-refresh middleware.
func DefaultAutoRefreshOptions() AutoRefreshOptions {
	return AutoRefreshOptions{
		HeaderName:       "Authorization",
		TokenType:        "Bearer",
		RefreshThreshold: 15 * time.Minute,
		OnRefresh:        func(c *gin.Context, oldToken, newToken string) {},
	}
}

// AutoRefresh is a Gin middleware that automatically refreshes JWT tokens
// that are nearing their expiration time. This helps to provide a seamless experience
// for users by reducing the need for them to re-authenticate.
//
// This middleware should be used after Auth Middleware.
func AutoRefresh(opts AutoRefreshOptions) gin.HandlerFunc {
	headerName := opts.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	tokenType := opts.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	refreshThreshold := opts.RefreshThreshold
	if refreshThreshold <= 0 {
		refreshThreshold = 15 * time.Minute
	}

	onRefresh := opts.OnRefresh
	if onRefresh == nil {
		onRefresh = func(c *gin.Context, oldToken, newToken string) {}
	}

	return func(c *gin.Context) {
		// Process the request first,
		// then check if the token needs to be refreshed
		c.Next()

		// Skip if the response status is an error
		if c.Writer.Status() >= 400 {
			return
		}

		// Get token from context (set by AuthMiddleware)
		tokenInterface, exists := c.Get(CtxKeyToken)
		if !exists {
			return
		}

		tokenObj, ok := tokenInterface.(*jwt.Token)
		if !ok {
			return
		}

		// Check if token is nearing expiration
		if time.Until(tokenObj.ExpiresAt) > refreshThreshold {
			return
		}

		// Get the original token string from the Authorization header
		authHeader := c.GetHeader(headerName)
		if authHeader == "" {
			return
		}

		// Extract token string from the Authorization header
		tokenString := authHeader
		if tokenType != "" {
			prefix := tokenType + " "
			if !strings.HasPrefix(authHeader, prefix) {
				return
			}
			tokenString = authHeader[len(prefix):]
		}

		// Refresh token
		newTokenString, err := opts.TokenService.RefreshToken(tokenString)
		if err != nil {
			return
		}

		onRefresh(c, tokenString, newTokenString)

		// Set the new token in the response header
		c.Header("X-New-Token", newTokenString)
	}
}
