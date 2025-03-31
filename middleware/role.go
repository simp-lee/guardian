package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/rbac"
)

// RoleOptions defines configuration options for the role middleware.
type RoleOptions struct {
	RBACService   rbac.Service
	RequiredRoles []string
	ErrorHandler  func(*gin.Context, error)
	OnGranted     func(c *gin.Context, userID string, roles []string)
	OnDenied      func(c *gin.Context, userID string, roles []string)
}

// DefaultRoleOptions returns default options for the role middleware.
func DefaultRoleOptions() RoleOptions {
	return RoleOptions{
		ErrorHandler: DefaultRoleErrorHandler,
		OnGranted:    func(*gin.Context, string, []string) {},
		OnDenied:     func(*gin.Context, string, []string) {},
	}
}

// Role checks if a user has any of the specified roles.
// It enables restricting access to routes based on user roles rather than
// specific permissions.
//
// This middleware must be used after Auth Middleware, as it relies on
// the user ID being set in the request context.
func Role(opts RoleOptions) gin.HandlerFunc {
	handleError := opts.ErrorHandler
	if handleError == nil {
		handleError = DefaultRoleErrorHandler
	}

	onGranted := opts.OnGranted
	if onGranted == nil {
		onGranted = func(c *gin.Context, userID string, roles []string) {}
	}

	onDenied := opts.OnDenied
	if onDenied == nil {
		onDenied = func(c *gin.Context, userID string, roles []string) {}
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

		// Get user roles
		userRoles, err := opts.RBACService.GetUserRoles(userID)
		if err != nil {
			handleError(c, err)
			return
		}

		// Check if the user has any of the required roles
		hasRequiredRole := false
		userRolesMap := make(map[string]bool)
		for _, role := range userRoles {
			userRolesMap[role] = true
		}

		// Check if any of the required roles are present in the user's roles
		for _, role := range opts.RequiredRoles {
			if userRolesMap[role] {
				hasRequiredRole = true
				break
			}
		}

		if !hasRequiredRole {
			onDenied(c, userID, opts.RequiredRoles)
			handleError(c, ErrUserDoesNotHaveRole)
			return
		}

		onGranted(c, userID, opts.RequiredRoles)

		c.Next()
	}
}
