package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRoleMiddlewareWithRequiredRole tests the role middleware with a user who has the required role
func TestRoleMiddlewareWithRequiredRole(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		getUserRolesFunc: func(userID string) ([]string, error) {
			if userID == "test-user" {
				return []string{"user", "editor"}, nil
			}
			return []string{}, nil
		},
	}

	roleOpts := RoleOptions{
		RBACService:   mockRBAC,
		RequiredRoles: []string{"editor", "admin"},
		OnGranted: func(c *gin.Context, userID string, roles []string) {
			c.Set("role_granted", true)
		},
	}

	// Create a new router
	router := setupRouter()
	router.Use(func(ctx *gin.Context) {
		ctx.Set(CtxKeyUserID, "test-user")
		ctx.Next()
	})

	// Create a test route with role middleware
	router.GET("/admin-area", Role(roleOpts), func(c *gin.Context) {
		hasAccess, exists := c.Get("role_granted")
		if !exists || !hasAccess.(bool) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OnGranted callback not executed"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/admin-area", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, w.Code)
	}

	if !strings.Contains(w.Body.String(), "success") {
		t.Errorf("Expected success message but got '%s'", w.Body.String())
	}
}

// TestRoleMiddlewareWithoutRequiredRole tests the role middleware with a user who doesn't have the required role
func TestRoleMiddlewareWithoutRequiredRole(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		getUserRolesFunc: func(userID string) ([]string, error) {
			if userID == "test-user" {
				return []string{"user"}, nil
			}
			return []string{}, nil
		},
	}

	deniedCalled := false
	roleOpts := RoleOptions{
		RBACService:   mockRBAC,
		RequiredRoles: []string{"editor", "admin"},
		OnDenied: func(c *gin.Context, userID string, roles []string) {
			deniedCalled = true
		},
	}

	// Create a new router
	router := setupRouter()
	router.Use(func(c *gin.Context) {
		c.Set(CtxKeyUserID, "test-user")
		c.Next()
	})

	// Create a test route with role middleware
	router.GET("/admin-area", Role(roleOpts), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/admin-area", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d but got %d", http.StatusForbidden, w.Code)
	}

	if !deniedCalled {
		t.Errorf("Expected OnDenied callback to be called but it was not")
	}

	if !strings.Contains(w.Body.String(), "user does not have required role") {
		t.Errorf("Expected error message 'user does not have required role' but got '%s'", w.Body.String())
	}
}

// TestRoleMiddlewareNoUserID tests the role middleware when user ID is not set
func TestRoleMiddlewareNoUserID(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		getUserRolesFunc: func(userID string) ([]string, error) {
			return []string{"user"}, nil
		},
	}

	roleOpts := RoleOptions{
		RBACService:   mockRBAC,
		RequiredRoles: []string{"admin"},
	}

	// Create a new router
	router := setupRouter()

	// Create a test route with role middleware but no user ID set
	router.GET("/admin-area", Role(roleOpts), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/admin-area", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d but got %d", http.StatusUnauthorized, w.Code)
	}

	if !strings.Contains(w.Body.String(), "unauthorized") {
		t.Errorf("Expected error message 'Unauthorized' but got '%s'", w.Body.String())
	}
}

// TestRoleMiddlewareWithError tests the role middleware when RBAC service returns an error
func TestRoleMiddlewareWithError(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		getUserRolesFunc: func(userID string) ([]string, error) {
			return nil, ErrUserNotFound
		},
	}

	errorHandled := false
	roleOpts := RoleOptions{
		RBACService:   mockRBAC,
		RequiredRoles: []string{"admin"},
		ErrorHandler: func(c *gin.Context, err error) {
			errorHandled = true
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Custom error handler: " + err.Error()})
			c.Abort()
		},
	}

	// Create a new router
	router := setupRouter()
	router.Use(func(c *gin.Context) {
		c.Set(CtxKeyUserID, "test-user")
		c.Next()
	})

	// Create a test route with role middleware
	router.GET("/admin-area", Role(roleOpts), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/admin-area", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d but got %d", http.StatusInternalServerError, w.Code)
	}

	if !errorHandled {
		t.Errorf("Expected error handler to be called but it was not")
	}

	if !strings.Contains(w.Body.String(), "Custom error handler") {
		t.Errorf("Expected error message 'Failed to get user roles' but got '%s'", w.Body.String())
	}
}
