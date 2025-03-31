package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/rbac"
)

// PermissionOptions defines configuration options for the permission middleware.
type PermissionOptions struct {
	RBACService  rbac.Service
	Resource     string
	Action       string
	ErrorHandler func(*gin.Context, error)
	OnGranted    func(c *gin.Context, userID, resource, action string)
	OnDenied     func(c *gin.Context, userID, resource, action string)
}

// DefaultPermissionOptions returns default options for the permission middleware.
func DefaultPermissionOptions() PermissionOptions {
	return PermissionOptions{
		ErrorHandler: DefaultPermissionErrorHandler,
		OnGranted:    func(*gin.Context, string, string, string) {},
		OnDenied:     func(*gin.Context, string, string, string) {},
	}
}

// Permission is a Gin middleware that checks if a user has
// permission to access a specific resource and perform an action.
// It uses the RBAC service to verify permissions based on the user's roles.
//
// This middleware must be used after Auth Middleware, as it relies on
// the user ID being set in the request context.
func Permission(opts PermissionOptions) gin.HandlerFunc {
	if opts.Resource == "" {
		panic(ErrInvalidResource)
	}

	if opts.Action == "" {
		panic(ErrInvalidAction)
	}

	handleError := opts.ErrorHandler
	if handleError == nil {
		handleError = DefaultPermissionErrorHandler
	}

	onGranted := opts.OnGranted
	if onGranted == nil {
		onGranted = func(c *gin.Context, userID, resource, action string) {}
	}

	onDenied := opts.OnDenied
	if onDenied == nil {
		onDenied = func(c *gin.Context, userID, resource, action string) {}
	}

	return func(c *gin.Context) {
		// Get user ID from context
		userIDVal, exists := c.Get(CtxKeyUserID)
		if !exists {
			handleError(c, ErrUnauthorized)
			return
		}
		userID := userIDVal.(string)
		if userID == "" {
			handleError(c, ErrUnauthorized)
			return
		}

		// Check permission
		hasPermission, err := opts.RBACService.HasPermission(userID, opts.Resource, opts.Action)
		if err != nil {
			handleError(c, err)
			return
		}

		if !hasPermission {
			onDenied(c, userID, opts.Resource, opts.Action)
			handleError(c, ErrForbidden)
			return
		}

		onGranted(c, userID, opts.Resource, opts.Action)

		c.Next()
	}
}
