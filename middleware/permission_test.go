package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestPermissionMiddlewareSuccess tests the permission middleware with a user who has permission
func TestPermissionMiddlewareSuccess(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		hasPermissionFunc: func(userID string, resource string, action string) (bool, error) {
			if userID == "test-user" && resource == "articles" && action == "read" {
				return true, nil
			}
			return false, nil
		},
	}

	// Create a new router
	router := setupRouter()

	// Create a test route with permissions
	router.GET("/articles", func(c *gin.Context) {
		// Manually set user ID since we're not using AuthMiddleware
		c.Set(CtxKeyUserID, "test-user")
		c.Next()
	}, Permission(PermissionOptions{
		RBACService: mockRBAC,
		Resource:    "articles",
		Action:      "read",
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/articles", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, w.Code)
	}
}

// TestPermissionMiddlewareForbidden tests the permission middleware with a user who doesn't have permission
func TestPermissionMiddlewareForbidden(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		hasPermissionFunc: func(userID string, resource string, action string) (bool, error) {
			return false, nil
		},
	}

	// Create a new router
	router := setupRouter()

	// Create a test route with permissions
	router.GET("/articles", func(c *gin.Context) {
		// Manually set user ID
		c.Set(CtxKeyUserID, "test-user")
		c.Next()
	}, Permission(PermissionOptions{
		RBACService: mockRBAC,
		Resource:    "articles",
		Action:      "read",
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/articles", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status code %d but got %d", http.StatusForbidden, w.Code)
	}

	if !strings.Contains(w.Body.String(), "middleware: forbidden") {
		t.Errorf("Expected error message 'middleware: forbidden' but got '%s'", w.Body.String())
	}
}

// TestPermissionMiddlewareNoUserID tests the permission middleware when user ID is not set
func TestPermissionMiddlewareNoUserID(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		hasPermissionFunc: func(userID string, resource string, action string) (bool, error) {
			return true, nil
		},
	}

	// Create a new router
	router := setupRouter()

	// Create a test route with permissions but no user ID set
	router.GET("/articles", Permission(PermissionOptions{
		RBACService: mockRBAC,
		Resource:    "articles",
		Action:      "read",
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/articles", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d but got %d", http.StatusUnauthorized, w.Code)
	}

	if !strings.Contains(w.Body.String(), "unauthorized") {
		t.Errorf("Expected error message 'unauthorized' but got '%s'", w.Body.String())
	}
}

// TestPermissionMiddlewareWithError tests the permission middleware when RBAC service returns an error
func TestPermissionMiddlewareWithError(t *testing.T) {
	// Create a mock RBAC service
	mockRBAC := &mockRBACService{
		hasPermissionFunc: func(userID string, resource string, action string) (bool, error) {
			return false, ErrRoleNotFound
		},
	}

	// Create a custom error handler
	customErrorHandler := func(c *gin.Context, err error) {
		c.JSON(http.StatusInternalServerError, gin.H{"rbac_error": err.Error()})
		c.Abort()
	}

	// Create a new router
	router := setupRouter()

	// Create a test route with permissions and custom error handler
	router.GET("/articles", func(c *gin.Context) {
		c.Set(CtxKeyUserID, "test-user")
		c.Next()
	}, Permission(PermissionOptions{
		RBACService:  mockRBAC,
		Resource:     "articles",
		Action:       "read",
		ErrorHandler: customErrorHandler,
	}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request
	req, _ := http.NewRequest("GET", "/articles", nil)
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status code %d but got %d", http.StatusInternalServerError, w.Code)
	}

	if !strings.Contains(w.Body.String(), "rbac_error") {
		t.Errorf("Expected custom error format but got '%s'", w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "invalid role ID") {
		t.Errorf("Expected error message 'invalid role ID' but got '%s'", w.Body.String())
	}
}
