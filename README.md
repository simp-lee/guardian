# Guardian: Go Authentication & Authorization Library

`Guardian` is a comprehensive security library specifically designed for `Gin` framework applications, providing role-based access control (RBAC) with JWT authentication to secure your Go APIs.

## Features

- **Role-Based Access Control (RBAC)**: Define granular permissions through roles
- **JWT Authentication**: Secure token generation, validation, and refreshing
- **Gin Middleware Integration**: Drop-in security middleware for Gin web applications
- **Permission Management**: Resource and action-based permission checks
- **Token Lifecycle Management**: Generate, validate, refresh, and revoke tokens
- **Rate Limiting**: Protection against brute force attacks
- **Flexible Storage**: In-memory storage by default with customizable backends
- **Hierarchical Resource Paths**: Support for nested resource permissions with wildcards
- **Auto Refresh**: Automatically refresh tokens before expiration
- **Custom Error Handling**: Fine-grained control over error responses
- **Event Callbacks**: Hook into authentication and authorization events

## Installation

```bash
go get github.com/simp-lee/guardian
```

## Quick Start

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/middleware"
)

func main() {
    // Initialize Guardian with a secret key
    g, err := guardian.New(
        guardian.WithSecretKey("your-secure-secret-key"),
    )
    if err != nil {
        panic(err)
    }
    defer g.Close() // Ensure resources are properly cleaned up
    
    // Create roles
    g.CreateRole("admin", "Administrator", "Full system access")
    g.CreateRole("user", "Regular User", "Basic access")
    
    // Define permissions
    g.AddRolePermission("admin", "users", "*")      // Admin can do anything with users
    g.AddRolePermission("user", "profile", "read")  // Users can read profiles
    g.AddRolePermission("user", "profile", "update") // Users can update profiles
    
    // Assign role to user
    g.AddUserRole("user123", "user")
    
    // Set up Gin router
    r := gin.Default()
    
    // Public routes
    r.POST("/login", g.RateLimit(), func(c *gin.Context) {
        // Validate credentials (implementation not shown)
        userID := "user123" // Retrieved from authentication
        
        // Generate JWT token with 24-hour validity
        token, err := g.GenerateToken(userID, 24*time.Hour)
        if err != nil {
            c.JSON(500, gin.H{"error": "Failed to generate token"})
            return
        }
        
        c.JSON(200, gin.H{"token": token})
    })
    
    // Protected routes
    protected := r.Group("/api")
    protected.Use(g.Auth()) // Apply authentication middleware
    
    protected.GET("/profile", func(c *gin.Context) {
        // After authentication, user ID is available in context
        userID := c.GetString(middleware.CtxKeyUserID)
        c.JSON(200, gin.H{"message": "Profile for user: " + userID})
    })
    
    // Route with permission check
    protected.POST("/users", g.RequirePermission("users", "create"), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "User created"})
    })
    
    // Route with role check
    protected.GET("/admin", g.RequireRole([]string{"admin"}), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Admin area"})
    })
    
    r.Run(":8080")
}
```

## Core Concepts

### Authentication

`Guardian` uses JWT (JSON Web Tokens) for authentication. The workflow is:

1. **Generate Token**: After verifying user credentials, generate a token containing the user's ID and roles
2. **Validate Token**: Guardian validates tokens during requests using the `Auth()` middleware
3. **Token Refresh**: Optionally refresh tokens before expiration to maintain session

```go
// Generate token with 1 hour validity
token, err := g.GenerateToken("user123", time.Hour)

// Refresh token before expiration
newToken, err := g.RefreshToken(oldToken)

// Revoke token when needed (logout, etc.)
g.RevokeToken(token)

// Revoke all tokens for a user (password change, security issue)
g.RevokeAllUserTokens("user123")
```

### Token Structure

From the JWT service, parsed tokens provide the following information:

```go
type Token struct {
    UserID    string       // User ID
    Roles     []string     // User's role list
    ExpiresAt time.Time    // Token expiration time
    IssuedAt  time.Time    // Token issue time
    TokenID   string       // Unique token identifier
}
```

### Roles and Permissions

Guardian's RBAC system consists of:

- **Roles**: Named collections of permissions (e.g., "admin", "editor")
- **Permissions**: Defined as resource + action pairs (e.g., "articles:read")
- **Users**: Assigned roles that grant them permissions

```go
// Create a role
g.CreateRole("editor", "Content Editor", "Can manage content")

// Add permissions to role
g.AddRolePermission("editor", "articles", "create")
g.AddRolePermission("editor", "articles", "update")
g.AddRolePermission("editor", "articles", "delete")
g.AddRolePermission("editor", "articles", "read")

// Add multiple permissions at once
g.AddRolePermissions("editor", "comments", []string{"create", "read", "update"})

// Assign role to user
g.AddUserRole("user123", "editor")

// Check if user has specific permission
hasPermission, _ := g.HasPermission("user123", "articles", "update")
```

### Hierarchy Notation

Resources can be organized in hierarchies using the forward slash (`/`) as a separator:
    
```
articles/draft
articles/published
users/profiles
users/settings
```

### Wildcard Permissions

The wildcard character (`*`) can be used in several ways:

1. **Action wildcard**: `"*"` matches any action on a specific resource
```go
g.AddRolePermission("admin", "articles", "*")  // Admin can perform any action on articles
```

2. **Resource wildcard**: `"*"` matches any resource for a specific action
```go
g.AddRolePermission("reviewer", "*", "read")  // Reviewer can read any resource
```

3. **Global wildcard**: `"*"` for both resource and action grants full access
```go
g.AddRolePermission("superadmin", "*", "*")  // Superadmin has full access
```

4. **Hierarchical wildcard**: `"resource/*"` matches all sub-resources
```go
g.AddRolePermission("editor", "articles/*", "update")  // Editor can update any article sub-resource
```

### Hierarchical Permission Resolution

When checking permissions for a hierarchical resource path, `Guardian` uses the following process:

1. First checks for an exact match on the specific resource and action
2. Then checks for wildcard actions (`*`) on the specific resource
3. Then checks for the specific action on wildcard resources (`*`)
4. Then checks for wildcard permissions on wildcard resources (`*`, `*`)
5. Finally traverses up the resource hierarchy, checking parent resources with wildcards

For example, when checking permission for `"articles/draft/section"` with `"edit"` action:

1. Checks `"articles/draft/section"` with `"edit"` permission
2. Checks `"articles/draft/section"` with `"*"` permission
3. Checks `"*"` with `"edit"` permission
4. Checks `"*"` with `"*"` permission
5. Checks hierarchical wildcards:
  - `"articles/draft/*"` with `"edit"` permission
  - `"articles/draft/*"` with `"*"` permission
  - `"articles/*"` with `"edit"` permission
  - `"articles/*"` with `"*"` permission

This hierarchical resolution enables efficient permission structures where higher-level permissions automatically apply to sub-resources without requiring explicit definitions.

**Important**: Permissions are inherited ONLY through explicit wildcard patterns. A permission on `"articles/drafts"` (without wildcard) will NOT automatically apply to `"articles/drafts/special"`.

**Examples**:

```go
// Set up resource hierarchy permissions
g.AddRolePermission("contentManager", "content/*", "read")   // Can read all content
g.AddRolePermission("articleEditor", "content/articles/*", "edit")  // Can edit all articles
g.AddRolePermission("draftEditor", "content/articles/drafts/*", "publish")  // Can publish drafts

// These permissions apply automatically:
// - contentManager can read content/articles, content/videos, etc.
// - articleEditor can edit content/articles/published, content/articles/drafts, etc.
// - draftEditor can publish any draft article

// Check permissions
hasPermission, _ := g.HasPermission("user123", "content/articles/drafts/article-1", "read")
// Returns true if user123 has contentManager role (due to content/* permission)
```

This approach significantly reduces the number of permission entries required while maintaining granular control over your resources.

### Middleware

`Guardian` provides middleware functions specifically for the `Gin` framework. When using `Guardian` middleware, the order is important:

1. **g.Auth()** should be applied first to authenticate users
2. **g.RequireRole()** or **g.RequirePermission()** should be applied after Auth
3. **g.RateLimit()** can be applied independently, typically for public endpoints like login

```go
// Correct order
protected := r.Group("/api")
protected.Use(g.Auth())  // Authenticate first
protected.Use(g.RequireRole([]string{"admin"}))  // Then check roles

// Apply rate limiting to login endpoint
r.POST("/login", g.RateLimit(), loginHandler)
```

### Context Values

After successful authentication, Guardian's Auth middleware sets the following keys in the `Gin` context:

```go
// Access authenticated user ID
userID := c.GetString(middleware.CtxKeyUserID)

// Access user roles (if any)
roles := c.GetStringSlice(middleware.CtxKeyRoles)

// Access the full parsed token object
token := c.MustGet(middleware.CtxKeyToken).(*jwt.Token)
```

These context values are available in all route handlers that execute after the Auth middleware. This allows your API handlers to access user information without having to parse the token again.

Example protected route handler:

```go
protected.GET("/profile", func(c *gin.Context) {
    // User ID is automatically available from context
    userID := c.GetString(middleware.CtxKeyUserID)
    
    // You can use the user ID to fetch user data
    userData, err := userService.GetUserProfile(userID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to get user data"})
        return
    }
    
    c.JSON(200, userData)
})
```

Note that these context keys are only set after the Auth middleware has processed a request with a valid token. They will not be available in routes that don't use the Auth middleware (like your login endpoint).

## Advanced Configuration

`Guardian` can be configured with various options:

```go
g, _ := guardian.New(
    // Required: Secret key for JWT signing
    guardian.WithSecretKey("your-secure-secret-key"),
    
    // Optional: Custom storage implementation
    guardian.WithStorage(myCustomStorage),
    
    // Optional: Enable auto-refresh when tokens are near expiration
    guardian.WithAutoRefresh(30 * time.Minute),
    
    // Optional: Custom token header name
    guardian.WithHeaderName("X-Auth-Token"),
    
    // Optional: Set the cleanup interval for expired tokens
    guardian.WithCleanupInterval(2 * time.Hour),
)
```

### Authentication Middleware Options

```go
g.Auth(
    // Custom authentication header name
    guardian.WithAuthHeaderName("X-API-Token"),
    
    // Custom token type (default is "Bearer")
    guardian.WithAuthTokenType("Custom"),
    
    // Callback for successful authentication
    guardian.OnAuthSuccess(func(c *gin.Context, token *jwt.Token) {
        // Custom handling logic
    }),
    
    // Callback for authentication failure
    guardian.OnAuthFailure(func(c *gin.Context, err error) {
        // Custom handling logic
    }),
    
    // Custom error handler
    guardian.WithAuthErrorHandler(func(c *gin.Context, err error) {
        c.JSON(401, gin.H{"custom_error": err.Error()})
        c.Abort()
    }),
)
```

### Auto Refresh Options

If you've enabled auto-refresh in the main configuration:

```go
// Enable auto-refresh in the Guardian constructor
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret"),
    guardian.WithAutoRefresh(15 * time.Minute), // Refresh when less than 15 minutes remaining
)

// Configure specific authentication middleware options, including token refresh handling
g.Auth(
    // Callback when a token is refreshed
    guardian.OnTokenRefresh(func(c *gin.Context, oldToken, newToken string) {
        // Log refresh event or perform other actions
        log.Printf("Token refreshed: %s -> %s", oldToken, newToken)
    }),
    
    // Custom refresh threshold (overrides global setting)
    guardian.WithRefreshThreshold(10 * time.Minute),
)
```

When a token is automatically refreshed, the new token is returned in the HTTP response `X-New-Token` header. Clients should check for this header and use the new token in subsequent requests.

### Permission Middleware Options

```go
g.RequirePermission("articles", "edit",
    // Callback when permission is granted
    guardian.OnPermissionGranted(func(c *gin.Context, userID, resource, action string) {
        // Log access, etc.
    }),
    
    // Callback when permission is denied
    guardian.OnPermissionDenied(func(c *gin.Context, userID, resource, action string) {
        // Log denial, etc.
    }),
    
    // Custom error handler
    guardian.WithPermissionErrorHandler(func(c *gin.Context, err error) {
        c.JSON(403, gin.H{"error": "No permission to access this resource"})
        c.Abort()
    }),
)
```

### Role Middleware Options

```go
g.RequireRole([]string{"admin", "editor"},
    // Callback when role check passes
    guardian.OnRoleGranted(func(c *gin.Context, userID string, roles []string) {
        // Log access, etc.
    }),
    
    // Callback when role check fails
    guardian.OnRoleDenied(func(c *gin.Context, userID string, roles []string) {
        // Log denial, etc.
    }),
    
    // Custom error handler
    guardian.WithRoleErrorHandler(func(c *gin.Context, err error) {
        c.JSON(403, gin.H{"error": "Higher privileges required"})
        c.Abort()
    }),
)
```

### Rate Limit Middleware Options

```go
g.RateLimit(
    // Set the requests per minute limit
    guardian.WithRateLimitRequestsPerMinute(60),
    
    // Set the burst limit for concurrent requests
    guardian.WithRateLimitBurst(10),
    
    // Set the cleanup interval for rate limit entries
    guardian.WithRateLimitCleanupInterval(5 * time.Minute),
    
    // Set the expiration time for rate limit entries
    guardian.WithRateLimitExpirationTime(10 * time.Minute),
    
    // Custom error handler
    guardian.WithRateLimitErrorHandler(func(c *gin.Context, err error) {
        c.JSON(429, gin.H{"error": "Too many requests, please try again later"})
        c.Abort()
    }),
    
    // Custom key extractor (for identifying request source)
    guardian.WithRateLimitKeyExtractor(func(c *gin.Context) string {
        // For example, extract user ID from custom header or JWT token
        return c.GetHeader("X-User-ID")
    }),
    
    // Callback when rate limit is triggered
    guardian.OnRateLimited(func(key string, c *gin.Context) {
        // Log rate-limited request
    }),
    
    // Callback for normal request (includes tokens remaining)
    guardian.OnRateLimitRequest(func(key string, remaining int, c *gin.Context) {
        // Can be used for monitoring or adding custom response headers
    }),
)
```

The rate limit middleware adds the following headers to responses:

- `X-RateLimit-Limit`: Indicates the rate limit ceiling
- `X-RateLimit-Remaining`: Indicates the number of tokens remaining

## Storage Subsystem

`Guardian` uses a flexible `Storage` interface that allows different backends to be plugged in. By default, it uses an in-memory storage implementation, but you can provide your own implementation for persistence.

### Storage Interface

The `Storage` interface defines methods for managing roles, user-role associations, and permissions:

```go
type Storage interface {
    // Role management
    CreateRole(role *Role) error
    GetRole(roleID string) (*Role, error)
    UpdateRole(role *Role) error
    DeleteRole(roleID string) error
    ListRoles() ([]*Role, error)

    // User-Role management
    AddUserRole(userID, roleID string) error
    RemoveUserRole(userID, roleID string) error
    GetUserRoles(userID string) ([]string, error)

    // Permission management
    AddRolePermission(roleID, resource, action string) error
    RemoveRolePermission(roleID, resource string) error
    HasPermission(roleID, resource, action string) (bool, error)
}
```

### Role Structure

`Roles` are the central entity in the `RBAC` system:

```go
type Role struct {
    ID          string
    Name        string
    Description string
    Permissions map[string][]string // resource -> []actions
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

Each role contains a map of resources to actions, representing what actions are allowed on each resource.

### Using Custom Storage

You can implement your own storage backend by implementing the `Storage` interface. This allows you to persist roles, permissions, and user-role mappings in databases or other storage systems.

```go
// Create a custom storage implementation
type MyDatabaseStorage struct {
    db *sql.DB
    // ...other fields
}

// Implement all methods from the Storage interface
func (s *MyDatabaseStorage) CreateRole(role *Role) error {
    // Implementation that uses your database
}

// ... implement other methods

// Use your custom storage with Guardian
customStorage := NewMyDatabaseStorage(dbConnection)
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    guardian.WithStorage(customStorage),
)
```

### Memory Storage

By default, `Guardian` uses an in-memory implementation that stores all data in Go maps:

```go
// If no custom storage is provided, Guardian uses memory storage
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    // Memory storage will be used automatically
)
```

The memory storage implementation is suitable for testing or applications where persistence is not required. For production systems with high availability requirements, you should implement a custom storage backend that persists data to a database.

## Error Handling

`Guardian` provides several error types that can be checked and handled:

### JWT Errors
```go
jwt.ErrMissingSecretKey  // Secret key is not provided
jwt.ErrEmptyUserID       // User ID is empty
jwt.ErrTokenCreation     // Failed to create token
jwt.ErrInvalidToken      // Token is invalid
jwt.ErrExpiredToken      // Token has expired
jwt.ErrRevokedToken      // Token has been revoked
```

### RBAC Errors
```go
rbac.ErrInvalidRoleID             // Role ID is invalid or empty
rbac.ErrEmptyUserID               // User ID is empty
rbac.ErrInvalidResource           // Resource name is invalid
rbac.ErrInvalidAction             // Action name is invalid
rbac.ErrPermissionAlreadyExists   // Permission already exists for role
```

### Middleware Errors
```go
middleware.ErrUnauthorized        // User is not authenticated
middleware.ErrForbidden           // User is authenticated but not authorized
middleware.ErrTooManyRequests     // User exceeded rate limit
middleware.ErrUserDoesNotHaveRole // User doesn't have required role
middleware.ErrInvalidResource     // Resource name is empty
middleware.ErrInvalidAction       // Action name is empty
```

### Storage Errors
```go
storage.ErrRoleNotFound        // Role not found
storage.ErrRoleAlreadyExists   // Role already exists
storage.ErrUserAlreadyHasRole  // User already has the role
storage.ErrUserDoesNotHaveRole // User does not have the role
storage.ErrPermissionNotFound  // Permission not found
```

## Security Best Practices

1. **Use strong secret keys** and manage them securely (environment variables, secret management)
2. **Keep token lifetimes short** - hours rather than days when possible
3. **Revoke tokens** when users change passwords or during security incidents
4. **Apply rate limiting** to authentication endpoints
5. **Use HTTPS** for all production deployments
6. **Follow least privilege principle** when assigning permissions
7. **Regularly audit** role assignments and permissions
8. **Handle token refreshes** - Clients should monitor the X-New-Token header and update their stored token

## Complete API Reference

For the complete API reference, see the [godoc documentation](https://pkg.go.dev/github.com/simp-lee/guardian).

## License

MIT License