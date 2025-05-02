// Package guardian provides a role-based access control (RBAC) system with
// token-based authentication for securing APIs and web applications built with the Gin framework.
package guardian

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/jwt"
	"github.com/simp-lee/guardian/middleware"
	"github.com/simp-lee/guardian/rbac"
	"github.com/simp-lee/guardian/storage"
)

// Guardian manages authentication and authorization for a Gin application.
// It combines JWT-based authentication with role-based access control (RBAC)
// to provide a comprehensive security solution.
type Guardian struct {
	rbac             rbac.Service
	jwt              jwt.Service
	config           Config
	cleanupFunctions []func() // functions to call when closing
}

// New creates a new Guardian instance with the provided options.
// It requires at least a secret key for JWT token signing.
//
// Example:
//
//	g, err := guardian.New(
//	    guardian.WithSecretKey("your-secure-secret-key"),
//	    guardian.WithAutoRefresh(30 * time.Minute),
//	)
//	if err != nil {
//	    // handle error
//	}
//	defer g.Close()
func New(options ...Option) (*Guardian, error) {
	config := DefaultConfig()
	for _, option := range options {
		if option == nil {
			continue
		}
		option(&config)
	}

	if config.SecretKey == "" {
		return nil, jwt.ErrMissingSecretKey
	}

	if config.Storage == nil {
		config.Storage = storage.NewMemoryStorage()
	} else if config.EnableCache {
		// Wrap the provided storage with caching capabilities
		config.Storage = storage.NewCachedStorage(config.Storage, config.CacheConfig)
	}

	jwtService, err := jwt.New(&jwt.Config{
		SecretKey:       config.SecretKey,
		CleanupInterval: config.CleanupInterval,
	})
	if err != nil {
		return nil, err
	}

	return &Guardian{
		rbac:             rbac.New(config.Storage),
		jwt:              jwtService,
		config:           config,
		cleanupFunctions: make([]func(), 0),
	}, nil
}

// GenerateToken creates a new JWT token for the specified user.
// The token will automatically include all roles assigned to the user
// in the RBAC system. The token will expire after the specified duration.
//
// Parameters:
//   - userID: The unique identifier of the user
//   - expiresIn: How long the token should be valid for (e.g., 24*time.Hour)
//
// Returns:
//   - The generated JWT token string
//   - An error if token generation fails
//
// Example:
//
//	token, err := g.GenerateToken("user123", 24*time.Hour)
func (g *Guardian) GenerateToken(userID string, expiresIn time.Duration) (string, error) {
	roles, err := g.rbac.GetUserRoles(userID)
	if err != nil {
		return "", err
	}
	return g.jwt.GenerateToken(userID, roles, expiresIn)
}

// ValidateToken validates a token string and returns the token details if valid.
// It checks the token signature, expiration time, and whether it has been revoked.
//
// Parameters:
//   - tokenString: The JWT token string to validate
//
// Returns:
//   - Token details if valid
//   - An error if the token is invalid, expired, or revoked
//
// Example:
//
//	token, err := g.ValidateToken(tokenString)
//	if err != nil {
//	    // handle invalid token
//	}
//	userID := token.UserID
func (g *Guardian) ValidateToken(tokenString string) (*jwt.Token, error) {
	return g.jwt.ValidateToken(tokenString)
}

// RefreshToken refreshes an existing token and generates a new one.
// The new token will have the same user ID and roles as the original token,
// but with a new expiration time based on the duration of the original token.
//
// Parameters:
//   - tokenString: The JWT token string to refresh
//
// Returns:
//   - A new token string with extended expiration
//   - An error if the token cannot be refreshed
//
// Example:
//
//	newToken, err := g.RefreshToken(oldToken)
func (g *Guardian) RefreshToken(tokenString string) (string, error) {
	return g.jwt.RefreshToken(tokenString)
}

// RevokeToken invalidates a specific token string.
// This adds the token to a revocation list, preventing its future use.
//
// Parameters:
//   - tokenString: The JWT token string to revoke
//
// Returns:
//   - An error if the token cannot be revoked
//
// Example:
//
//	err := g.RevokeToken(tokenString)
func (g *Guardian) RevokeToken(tokenString string) error {
	return g.jwt.RevokeToken(tokenString)
}

// IsTokenRevoked checks if a token has been revoked.
//
// Parameters:
//   - tokenID: The ID of the token to check
//
// Returns:
//   - true if the token has been revoked, false otherwise
func (g *Guardian) IsTokenRevoked(tokenID string) bool {
	return g.jwt.IsTokenRevoked(tokenID)
}

// ParseToken parses a token string and returns the token details.
// Unlike ValidateToken, this does not check if the token is valid or revoked,
// only that it can be parsed.
//
// Parameters:
//   - tokenString: The JWT token string to parse
//
// Returns:
//   - Token details if parsable
//   - An error if the token cannot be parsed
func (g *Guardian) ParseToken(tokenString string) (*jwt.Token, error) {
	return g.jwt.ParseToken(tokenString)
}

// RevokeAllUserTokens invalidates all tokens for a user.
// This is useful when a user changes their password or when a security breach is suspected.
//
// Parameters:
//   - userID: The unique identifier of the user
//
// Returns:
//   - An error if the operation fails
//
// Example:
//
//	err := g.RevokeAllUserTokens("user123")
func (g *Guardian) RevokeAllUserTokens(userID string) error {
	return g.jwt.RevokeAllUserTokens(userID)
}

// ---------------------------------------------------------------------------
// Middleware methods for Gin framework
// ---------------------------------------------------------------------------

// Auth returns a middleware that authenticates requests using JWT tokens.
// It extracts the token from the Authorization header, validates it,
// and sets user information in the Gin context.
//
// If auto-refresh is enabled in the config, it also handles token refreshing.
// When a token is refreshed, the new token is sent in the X-New-Token header.
//
// After successful authentication, the following values are set in the context:
//   - "guardian:user_id": The user ID from the token
//   - "guardian:roles": The user's roles from the token
//   - "guardian:token": The parsed token object
//
// Parameters:
//   - opts: Optional configuration options for the middleware
//
// Returns:
//   - A Gin middleware function
//
// Example:
//
//	r := gin.Default()
//	protected := r.Group("/api")
//	protected.Use(g.Auth())
func (g *Guardian) Auth(opts ...AuthOption) gin.HandlerFunc {
	options := middleware.DefaultAuthOptions()
	options.TokenService = g.jwt
	options.HeaderName = g.config.HeaderName
	options.TokenType = g.config.TokenType

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&options)
	}

	auth := middleware.Auth(options)

	if !g.config.EnableAutoRefresh {
		return auth
	}

	// If auto-refresh is enabled, set up the refresh options.
	refreshOpts := middleware.DefaultAutoRefreshOptions()
	refreshOpts.TokenService = g.jwt
	refreshOpts.HeaderName = g.config.HeaderName
	refreshOpts.TokenType = g.config.TokenType
	refreshOpts.RefreshThreshold = g.config.RefreshThreshold

	refresh := middleware.AutoRefresh(refreshOpts)

	// Chain the auth and refresh middlewares together.
	return func(c *gin.Context) {
		auth(c)
		if !c.IsAborted() {
			refresh(c)
		}
	}
}

// RequirePermission returns a middleware that requires a specific permission.
// The middleware checks if the authenticated user has the specified permission
// (resource + action) before allowing access to the route.
//
// This middleware should be used after the Auth middleware.
//
// Parameters:
//   - resource: The resource to check permission for
//   - action: The action to check permission for
//   - opts: Optional configuration options for the middleware
//
// Returns:
//   - A Gin middleware function
//
// Example:
//
//	r.GET("/articles", g.Auth(), g.RequirePermission("articles", "read"), getArticles)
func (g *Guardian) RequirePermission(resource, action string, opts ...PermissionOption) gin.HandlerFunc {
	options := middleware.DefaultPermissionOptions()
	options.RBACService = g.rbac
	options.Resource = resource
	options.Action = action

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&options)
	}

	return middleware.Permission(options)
}

// RequireRole returns a middleware that requires one of the specified roles.
// The middleware checks if the authenticated user has at least one of the
// required roles before allowing access to the route.
//
// This middleware should be used after the Auth middleware.
//
// Parameters:
//   - roles: A slice of role IDs, one of which is required for access
//   - opts: Optional configuration options for the middleware
//
// Returns:
//   - A Gin middleware function
//
// Example:
//
//	r.DELETE("/articles/:id", g.Auth(), g.RequireRole([]string{"admin", "editor"}), deleteArticle)
func (g *Guardian) RequireRole(roles []string, opts ...RoleOption) gin.HandlerFunc {
	options := middleware.DefaultRoleOptions()
	options.RBACService = g.rbac
	options.RequiredRoles = roles

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&options)
	}

	return middleware.Role(options)
}

// RateLimit returns a middleware that limits requests per minute.
// This helps protect APIs from abuse by limiting how many requests
// can be made within a time period.
//
// Parameters:
//   - opts: Optional configuration options for the middleware
//
// Returns:
//   - A Gin middleware function
//
// Example:
//
//	r.POST("/login", g.RateLimit(), loginHandler)
func (g *Guardian) RateLimit(opts ...RateLimitOption) gin.HandlerFunc {
	options := middleware.DefaultRateLimitOptions()
	options.CleanupInterval = g.config.CleanupInterval

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&options)
	}

	limiter, cleanup := middleware.RateLimit(options)

	// Save the cleanup function to call when closing.
	g.cleanupFunctions = append(g.cleanupFunctions, cleanup)

	return limiter
}

// Role type alias for convenience
type Role = rbac.Role

// CreateRole creates a new role.
//
// Parameters:
//   - id: The unique identifier for the role
//   - name: The display name for the role
//   - description: A description of the role
//
// Returns:
//   - An error if the role cannot be created
//
// Example:
//
//	err := g.CreateRole("admin", "Administrator", "Full system access")
func (g *Guardian) CreateRole(id, name, description string) error {
	return g.rbac.CreateRole(id, name, description)
}

// GetRole retrieves a role by ID.
//
// Parameters:
//   - roleID: The unique identifier of the role
//
// Returns:
//   - The role if found
//   - An error if the role cannot be found
func (g *Guardian) GetRole(roleID string) (*Role, error) {
	return g.rbac.GetRole(roleID)
}

// UpdateRole updates a role's name and description.
//
// Parameters:
//   - roleID: The unique identifier of the role
//   - name: The new display name
//   - description: The new description
//
// Returns:
//   - An error if the role cannot be updated
func (g *Guardian) UpdateRole(roleID, name, description string) error {
	return g.rbac.UpdateRole(roleID, name, description)
}

// DeleteRole deletes a role.
//
// Parameters:
//   - roleID: The unique identifier of the role
//
// Returns:
//   - An error if the role cannot be deleted
func (g *Guardian) DeleteRole(roleID string) error {
	return g.rbac.DeleteRole(roleID)
}

// ListRoles retrieves all roles.
//
// Returns:
//   - A slice of all roles
//   - An error if the roles cannot be retrieved
func (g *Guardian) ListRoles() ([]*Role, error) {
	return g.rbac.ListRoles()
}

// AddUserRole assigns a role to a user.
//
// Parameters:
//   - userID: The unique identifier of the user
//   - roleID: The unique identifier of the role
//
// Returns:
//   - An error if the role cannot be assigned
//
// Example:
//
//	err := g.AddUserRole("user123", "admin")
func (g *Guardian) AddUserRole(userID, roleID string) error {
	return g.rbac.AddUserRole(userID, roleID)
}

// RemoveUserRole removes a role from a user.
//
// Parameters:
//   - userID: The unique identifier of the user
//   - roleID: The unique identifier of the role
//
// Returns:
//   - An error if the role cannot be removed
func (g *Guardian) RemoveUserRole(userID, roleID string) error {
	return g.rbac.RemoveUserRole(userID, roleID)
}

// GetUserRoles returns the roles assigned to a user.
//
// Parameters:
//   - userID: The unique identifier of the user
//
// Returns:
//   - A slice of role IDs assigned to the user
//   - An error if the roles cannot be retrieved
func (g *Guardian) GetUserRoles(userID string) ([]string, error) {
	return g.rbac.GetUserRoles(userID)
}

// AddRolePermission adds a permission to a role.
//
// Parameters:
//   - roleID: The unique identifier of the role
//   - resource: The resource to grant permission for
//   - action: The action to grant permission for
//
// Returns:
//   - An error if the permission cannot be added
//
// Example:
//
//	err := g.AddRolePermission("admin", "articles", "create")
func (g *Guardian) AddRolePermission(roleID, resource, action string) error {
	return g.rbac.AddRolePermission(roleID, resource, action)
}

// AddRolePermissions adds multiple permissions to a role.
//
// Parameters:
//   - roleID: The unique identifier of the role
//   - resource: The resource to grant permissions for
//   - actions: A slice of actions to grant permissions for
//
// Returns:
//   - An error if the permissions cannot be added
//
// Example:
//
//	err := g.AddRolePermissions("editor", "articles", []string{"create", "read", "update"})
func (g *Guardian) AddRolePermissions(roleID, resource string, actions []string) error {
	return g.rbac.AddRolePermissions(roleID, resource, actions)
}

// RemoveRolePermission removes a permission from a role.
//
// Parameters:
//   - roleID: The unique identifier of the role
//   - resource: The resource to remove permissions for
//
// Returns:
//   - An error if the permission cannot be removed
func (g *Guardian) RemoveRolePermission(roleID, resource string) error {
	return g.rbac.RemoveRolePermission(roleID, resource)
}

// HasPermission checks if a user has permission for an action on a resource.
// It supports hierarchical resource paths with wildcard matching.
//
// The permission check follows this order:
// 1. Exact match for resource and action
// 2. Wildcard action for the specific resource
// 3. Specific action for wildcard resource
// 4. Wildcard action for wildcard resource
// 5. Hierarchical parent resources with wildcards
//
// Important details about hierarchical resource permissions:
//   - Resource paths are separated by "/" (e.g., "articles/drafts/special")
//   - Wildcard inheritance works ONLY through explicit wildcard patterns
//   - A permission on "articles/drafts/*" will grant access to "articles/drafts/special"
//   - A permission on "articles/*" will grant access to any resource under "articles/"
//   - A permission on "articles/drafts" (without wildcard) will NOT automatically apply
//     to child resources like "articles/drafts/special"
//
// Examples:
// - Permission for "articles" with action "read":
//   - Grants access to: "articles" only
//   - Does NOT grant access to: "articles/draft"
//
// - Permission for "articles/*" with action "read":
//   - Grants access to: "articles/draft", "articles/published", "articles/draft/special"
//
// - Permission for "articles" with action "*":
//   - Grants ALL actions on "articles" only
//   - Does NOT grant actions on "articles/draft"
//
// - Permission for "articles/*" with action "*":
//   - Grants ALL actions on ALL resources under "articles/"
//
// Parameters:
//   - userID: The unique identifier of the user
//   - resource: The resource to check permission for
//   - action: The action to check permission for
//
// Returns:
//   - true if the user has permission, false otherwise
//   - An error if the permission check fails
//
// Example:
//
//	hasPermission, err := g.HasPermission("user123", "articles/drafts", "edit")
func (g *Guardian) HasPermission(userID, resource, action string) (bool, error) {
	return g.rbac.HasPermission(userID, resource, action)
}

// Close releases resources used by Guardian.
// It should be called when the application is shutting down to ensure
// proper cleanup of background goroutines and other resources.
//
// Example:
//
//	g, _ := guardian.New(guardian.WithSecretKey("your-secret-key"))
//	defer g.Close()
func (g *Guardian) Close() {
	if g.jwt != nil {
		g.jwt.Close()
	}

	// Close the storage.
	if closer, ok := g.config.Storage.(interface{ Close() error }); ok {
		_ = closer.Close()
	}

	// Call any cleanup functions.
	for _, cleanup := range g.cleanupFunctions {
		if cleanup != nil {
			cleanup()
		}
	}

	// Clear the cleanup functions slice.
	g.cleanupFunctions = nil
}

// GetCacheStats returns cache hit and miss statistics for roles and user-roles.
// This provides insights into cache performance and effectiveness.
//
// Returns:
//   - roleHits: Number of times roles were found in cache
//   - roleMisses: Number of times roles had to be fetched from storage
//   - userRoleHits: Number of times user roles were found in cache
//   - userRoleMisses: Number of times user roles had to be fetched from storage
//
// Example:
//
//	roleHits, roleMisses, userRoleHits, userRoleMisses := g.GetCacheStats()
//	hitRate := float64(roleHits) / float64(roleHits + roleMisses) * 100
//	fmt.Printf("Role cache hit rate: %.2f%%\n", hitRate)
func (g *Guardian) GetCacheStats() (roleHits, roleMisses, userRoleHits, userRoleMisses int64) {
	if cachedStorage, ok := g.config.Storage.(*storage.CachedStorage); ok {
		return cachedStorage.Stats()
	}
	return 0, 0, 0, 0
}

// GetCacheSize returns the current number of entries in the role and user-role caches.
// This helps monitor memory usage by the cache system.
//
// Returns:
//   - roleCacheSize: Number of roles currently stored in cache
//   - userRoleCacheSize: Number of user-role relationships currently stored in cache
//
// Example:
//
//	roleCacheSize, userRoleCacheSize := g.GetCacheSize()
//	fmt.Printf("Cache contains %d roles and %d user-role entries\n",
//	    roleCacheSize, userRoleCacheSize)
func (g *Guardian) GetCacheSize() (roleCacheSize, userRoleCacheSize int) {
	if cachedStorage, ok := g.config.Storage.(*storage.CachedStorage); ok {
		return cachedStorage.GetCacheSize()
	}
	return 0, 0
}

// ClearCache invalidates and removes all cached entries.
// This is useful after bulk permission changes or during testing.
//
// Example:
//
//	// After bulk role/permission updates
//	adminService.UpdateManyRoles()
//	g.ClearCache() // Ensure the cache reflects the new changes immediately
func (g *Guardian) ClearCache() {
	if cachedStorage, ok := g.config.Storage.(*storage.CachedStorage); ok {
		cachedStorage.ClearCache()
	}
}
