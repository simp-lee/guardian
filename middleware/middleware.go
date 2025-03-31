package middleware

import (
	"errors"

	"github.com/gin-gonic/gin"
)

// Context keys for data stored in the Gin context
const (
	CtxKeyUserID = "guardian:user_id"
	CtxKeyRoles  = "guardian:roles"
	CtxKeyToken  = "guardian:token"
)

// Common errors returned by middleware
var (
	ErrUnauthorized        = errors.New("middleware: unauthorized")
	ErrForbidden           = errors.New("middleware: forbidden")
	ErrTooManyRequests     = errors.New("middleware: too many requests")
	ErrUserDoesNotHaveRole = errors.New("middleware: user does not have required role")
	ErrInvalidResource     = errors.New("middleware: resource name cannot be empty")
	ErrInvalidAction       = errors.New("middleware: action name cannot be empty")
)

// Default error handlers
var (
	// DefaultAuthErrorHandler handles authentication errors
	DefaultAuthErrorHandler = func(c *gin.Context, err error) {
		c.AbortWithStatusJSON(401, gin.H{
			"error": err.Error(),
		})
	}

	// DefaultPermissionErrorHandler handles permission errors
	DefaultPermissionErrorHandler = func(c *gin.Context, err error) {
		status := 403
		if errors.Is(err, ErrUnauthorized) {
			status = 401
		}
		c.AbortWithStatusJSON(status, gin.H{
			"error": err.Error(),
		})
	}

	// DefaultRoleErrorHandler handles role errors
	DefaultRoleErrorHandler = func(c *gin.Context, err error) {
		status := 403
		if errors.Is(err, ErrUnauthorized) {
			status = 401
		}
		c.AbortWithStatusJSON(status, gin.H{
			"error": err.Error(),
		})
	}

	// DefaultRateLimitErrorHandler handles rate limit errors
	DefaultRateLimitErrorHandler = func(c *gin.Context, err error) {
		c.AbortWithStatusJSON(429, gin.H{
			"error": err.Error(),
		})
	}
)
