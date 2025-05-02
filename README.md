# Guardian: Go Authentication & Authorization Library

[English](#introduction) | [简体中文](#简介)

## Introduction

`Guardian` is a comprehensive security library specifically designed for `Gin` framework applications, providing role-based access control (RBAC) with JWT authentication to secure your Go APIs.

## Features

- **Role-Based Access Control (RBAC)**: Define granular permissions through roles
- **JWT Authentication**: Secure token generation, validation, and refreshing
- **Gin Middleware Integration**: Drop-in security middleware for Gin web applications
- **Permission Management**: Resource and action-based permission checks
- **Token Lifecycle Management**: Generate, validate, refresh, and revoke tokens
- **Rate Limiting**: Protection against brute force attacks
- **Flexible Storage**: In-memory storage by default with SQL storage support (MySQL, PostgreSQL, SQLite) and customizable backends
- **Hierarchical Resource Paths**: Support for nested resource permissions with wildcards
- **High-Performance Caching**: Built-in multi-level caching system for improved access speed
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
    defer g.Close()
    
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

### Caching System

`Guardian` includes a high-performance multi-level caching system that significantly improves performance for frequently accessed data. The caching system automatically manages role and user permission data, reducing access to the underlying storage.

```go
// Enable caching with custom settings
g, _ := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithCache(true), // Enable caching (enabled by default)
    guardian.WithRoleCacheTTL(1 * time.Hour), // Time-to-live for role cache
    guardian.WithUserRoleCacheTTL(30 * time.Minute), // Time-to-live for user-role relations
    guardian.WithCacheCleanupInterval(10 * time.Minute), // Cache cleanup interval
)

// Or use a completely custom cache configuration
cacheConfig := storage.CacheConfig{
    EnableRoleCache:      true,
    RoleCacheTTL:         2 * time.Hour,
    EnableUserRoleCache:  true,
    UserRoleCacheTTL:     1 * time.Hour,
    CleanupInterval:      15 * time.Minute,
    MaxRoleCacheSize:     2000,  // Maximum of 2000 roles in cache
    MaxUserRoleCacheSize: 10000, // Maximum of 10000 user-role relations in cache
}

g, _ := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithCacheConfig(cacheConfig),
)
```

The caching system provides the following capabilities:

1. **Role Caching**: Caches role definitions and permissions, reducing the overhead of repeatedly fetching the same roles from storage.
2. **User-Role Caching**: Caches user-role relationships to speed up permission checks.
3. **Automatic Invalidation**: Automatically invalidates relevant caches when roles or permissions change.
4. **Periodic Cleanup**: Periodically cleans up expired entries to prevent memory leaks.
5. **Size Limiting**: Configurable maximum cache entries to control memory usage.
6. **Performance Monitoring**: Built-in hit and miss rate statistics.

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

    // Optional: Enable role and permission caching
    guardian.WithCache(true),
    
    // Optional: Set role cache expiration time
    guardian.WithRoleCacheTTL(1 * time.Hour),
    
    // Optional: Set user-role cache expiration time
    guardian.WithUserRoleCacheTTL(30 * time.Minute),
    
    // Optional: Set cache cleanup interval
    guardian.WithCacheCleanupInterval(10 * time.Minute),
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
    // Enable global auto-refresh and set the default threshold
    // The token will be refreshed if its remaining validity is less than 15 minutes
    guardian.WithAutoRefresh(15 * time.Minute),
)
```

When you apply the Auth middleware and auto-refresh is enabled, the refresh functionality will be automatically included:

```go
// Apply standard authentication middleware 
router.Use(g.Auth())
```

For more control over the refresh behavior, you can manually configure the auto-refresh middleware:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/middleware"
)

// Apply the auto-refresh middleware with custom options
router.Use(middleware.AutoRefresh(
    // Callback when a token is refreshed
    guardian.OnTokenRefresh(func(c *gin.Context, oldToken, newToken string) {
        // Log refresh event or perform other actions
        log.Printf("Token refreshed: %s -> %s", oldToken, newToken)
    }),
    
    // Custom refresh threshold for this specific middleware instance
    // Overrides the global setting from Guardian constructor
    guardian.WithRefreshThreshold(10 * time.Minute),
))
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

## Storage Options

`Guardian` supports multiple storage backends for roles, permissions and user-role mappings:

### Memory Storage (Default)

By default, `Guardian` uses an in-memory storage implementation that stores all data in Go maps:

```go
// Using the default memory storage
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    // No storage option specified - memory storage will be used
)
```

Memory storage is suitable for testing or applications where persistence is not required. However, all data will be lost when the application restarts.

### SQL Storage

For production systems, `Guardian` provides SQL-based storage implementations that persist role and permission data to a database:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/storage"
    _ "github.com/go-sql-driver/mysql" // Import MySQL driver
)

// Create MySQL storage
sqlStorage, err := storage.CreateMySQLStorage(
    "user:password@tcp(127.0.0.1:3306)/guardian_db?parseTime=true"
)
if err != nil {
    log.Fatalf("Failed to create SQL storage: %v", err)
}

// Create Guardian instance with SQL storage
g, err := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithStorage(sqlStorage),
)
if err != nil {
    log.Fatalf("Failed to create Guardian: %v", err)
}
defer g.Close()
```

#### Supported Database Systems

Guardian currently supports the following database systems:

1. **MySQL/MariaDB**:
   ```go
   storage, err := storage.CreateMySQLStorage(
       "user:password@tcp(127.0.0.1:3306)/dbname?parseTime=true"
   )
   ```

2. **PostgreSQL**:
   ```go
   storage, err := storage.CreatePostgresStorage(
       "host=localhost port=5432 user=postgres password=secret dbname=guardian_db sslmode=disable"
   )
   ```

3. **SQLite**:
   ```go
   storage, err := storage.CreateSQLiteStorage("path/to/database.db")
   // Or use in-memory SQLite database
   storage, err := storage.CreateSQLiteStorage(":memory:")
   ```

#### Using with GORM

If your application already uses `GORM` for database access, you can integrate `Guardian` with your existing database connection:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/storage"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// Create GORM connection
dsn := "user:password@tcp(127.0.0.1:3306)/database?charset=utf8mb4&parseTime=True&loc=Local"
gormDB, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    log.Fatalf("Failed to connect to database: %v", err)
}

// Get the underlying *sql.DB instance
sqlDB, err := gormDB.DB()
if err != nil {
    log.Fatalf("Failed to get underlying sql.DB: %v", err)
}

// Create Guardian storage using the existing connection
guardianStorage, err := storage.NewSQLStorage(sqlDB)
if err != nil {
    log.Fatalf("Failed to create Guardian storage: %v", err)
}

// Create Guardian instance
g, err := guardian.New(
    guardian.WithSecretKey("your-secure-key"),
    guardian.WithStorage(guardianStorage),
)
```

#### Database Schema

When using SQL storage, `Guardian` automatically creates the following tables:

- `guardian_roles`: Stores role definitions and permissions
- `guardian_user_roles`: Stores user-role associations

The tables are created with `IF NOT EXISTS` clauses, so they won't conflict with existing tables.

### Database Driver Installation

Depending on your chosen database system, you'll need to install the appropriate driver:

```bash
# MySQL driver
go get github.com/go-sql-driver/mysql

# PostgreSQL driver
go get github.com/lib/pq

# SQLite driver (CGO required)
go get github.com/mattn/go-sqlite3

# SQLite driver (Pure Go, no CGO)
go get modernc.org/sqlite
```

### Custom Storage Implementation

You can implement your own storage backend by implementing the Storage interface:

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

    // Resource management
    Close() error
}
```

Then use your custom implementation with Guardian:

```go
customStorage := NewMyCustomStorage(...)
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    guardian.WithStorage(customStorage),
)
```

## Cache Management

`Guardian` provides complete control over the caching system, allowing you to fine-tune it according to application needs:

```go
// Get cache statistics
roleHits, roleMisses, userRoleHits, userRoleMisses := g.GetCacheStats()
fmt.Printf("Role Cache: Hit Rate %.2f%%\n", 
    float64(roleHits)/float64(roleHits+roleMisses)*100)
fmt.Printf("User Role Cache: Hit Rate %.2f%%\n", 
    float64(userRoleHits)/float64(userRoleHits+userRoleMisses)*100)

// Get current cache size
roleCacheSize, userRoleCacheSize := g.GetCacheSize()
fmt.Printf("Cache Size: %d roles, %d user role entries\n", 
    roleCacheSize, userRoleCacheSize)

// Clear all caches (e.g., after a bulk permission change)
g.ClearCache()
```

Adjust cache configuration to balance memory usage and performance:

```go
// Custom cache configuration suitable for large applications with many users but fewer roles
config := storage.CacheConfig{
    EnableRoleCache:      true,
    RoleCacheTTL:         4 * time.Hour,  // Roles do not change often, can be cached longer
    EnableUserRoleCache:  true,
    UserRoleCacheTTL:     30 * time.Minute,
    CleanupInterval:      10 * time.Minute,
    MaxRoleCacheSize:     500,    // System has fewer roles, appropriate limit
    MaxUserRoleCacheSize: 100000, // Large number of users, requires larger cache
}

g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    guardian.WithCacheConfig(config),
)
```

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


---

# Guardian: Go 认证与授权库

[English](#introduction) | [简体中文](#简介)

## 简介

`Guardian` 是专为 `Gin` 框架应用设计的全面安全库，提供了基于角色的访问控制 (RBAC) 和 JWT 认证，以保护您的 Go API 安全。

## 功能特点

- **基于角色的访问控制 (RBAC)**: 通过角色定义精细权限
- **JWT 认证**: 安全的令牌生成、验证和刷新
- **Gin 中间件集成**: 为 Gin Web 应用提供即插即用的安全中间件
- **权限管理**: 基于资源和操作的权限检查
- **令牌生命周期管理**: 生成、验证、刷新和撤销令牌
- **速率限制**: 防止暴力攻击
- **灵活的存储**: 默认内存存储，支持 SQL 存储 (MySQL, PostgreSQL, SQLite) 和自定义后端
- **分层资源路径**: 支持带通配符的嵌套资源权限
- **高性能缓存**: 内置多级缓存系统，提高访问速度
- **自动刷新**: 在过期前自动刷新令牌
- **自定义错误处理**: 对错误响应的精细控制
- **事件回调**: 挂接认证和授权事件

## 安装

```bash
go get github.com/simp-lee/guardian
```

## 快速开始

```go
package main

import (
    "time"
    "github.com/gin-gonic/gin"
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/middleware"
)

func main() {
    // 使用密钥初始化 Guardian
    g, err := guardian.New(
        guardian.WithSecretKey("your-secure-secret-key"),
    )
    if err != nil {
        panic(err)
    }
    defer g.Close()
    
    // 创建角色
    g.CreateRole("admin", "Administrator", "Full system access")
    g.CreateRole("user", "Regular User", "Basic access")
    
    // 定义权限
    g.AddRolePermission("admin", "users", "*")      // 管理员可以对用户做任何操作
    g.AddRolePermission("user", "profile", "read")  // 用户可以读取个人资料
    g.AddRolePermission("user", "profile", "update") // 用户可以更新个人资料
    
    // 分配角色给用户
    g.AddUserRole("user123", "user")
    
    // 设置 Gin 路由
    r := gin.Default()
    
    // 公开路由
    r.POST("/login", g.RateLimit(), func(c *gin.Context) {
        // 验证凭证(实现未显示)
        userID := "user123" // 从认证中获取
        
        // 生成24小时有效的JWT令牌
        token, err := g.GenerateToken(userID, 24*time.Hour)
        if err != nil {
            c.JSON(500, gin.H{"error": "Failed to generate token"})
            return
        }
        
        c.JSON(200, gin.H{"token": token})
    })
    
    // 受保护路由
    protected := r.Group("/api")
    protected.Use(g.Auth()) // 应用认证中间件
    
    protected.GET("/profile", func(c *gin.Context) {
        // 认证后，用户ID在上下文中可用
        userID := c.GetString(middleware.CtxKeyUserID)
        c.JSON(200, gin.H{"message": "Profile for user: " + userID})
    })
    
    // 带权限检查的路由
    protected.POST("/users", g.RequirePermission("users", "create"), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "User created"})
    })
    
    // 带角色检查的路由
    protected.GET("/admin", g.RequireRole([]string{"admin"}), func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Admin area"})
    })
    
    r.Run(":8080")
}
```

## 核心概念

### 认证

`Guardian` 使用 JWT (JSON Web Tokens) 进行认证。工作流程是:

1. **生成令牌**: 验证用户凭证后，生成包含用户ID和角色的令牌
2. **验证令牌**: Guardian 使用 `Auth()` 中间件在请求期间验证令牌
3. **令牌刷新**: 可选择在过期前刷新令牌以维持会话

```go
// 生成1小时有效期的令牌
token, err := g.GenerateToken("user123", time.Hour)

// 在过期前刷新令牌
newToken, err := g.RefreshToken(oldToken)

// 在需要时撤销令牌(登出等)
g.RevokeToken(token)

// 撤销用户的所有令牌(密码更改，安全问题)
g.RevokeAllUserTokens("user123")
```

### 令牌结构

从 JWT 服务解析的令牌提供以下信息:

```go
type Token struct {
    UserID    string       // 用户ID
    Roles     []string     // 用户角色列表
    ExpiresAt time.Time    // 令牌过期时间
    IssuedAt  time.Time    // 令牌签发时间
    TokenID   string       // 唯一令牌标识符
}
```

### 角色和权限

Guardian 的 RBAC 系统包含:

- **角色**: 权限的命名集合(如"admin"、"editor")
- **权限**: 定义为资源+操作对(如"articles:read")
- **用户**: 分配角色以授予权限

```go
// 创建角色
g.CreateRole("editor", "Content Editor", "Can manage content")

// 给角色添加权限
g.AddRolePermission("editor", "articles", "create")
g.AddRolePermission("editor", "articles", "update")
g.AddRolePermission("editor", "articles", "delete")
g.AddRolePermission("editor", "articles", "read")

// 一次添加多个权限
g.AddRolePermissions("editor", "comments", []string{"create", "read", "update"})

// 为用户分配角色
g.AddUserRole("user123", "editor")

// 检查用户是否有特定权限
hasPermission, _ := g.HasPermission("user123", "articles", "update")
```

### 缓存系统

Guardian 包含一个高性能的多级缓存系统，显著提高频繁访问数据的性能。缓存系统自动管理角色和用户权限数据，减少对底层存储的访问。

```go
// 启用缓存并配置自定义设置
g, _ := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithCache(true), // 启用缓存(默认为启用)
    guardian.WithRoleCacheTTL(1 * time.Hour), // 角色缓存的存活时间
    guardian.WithUserRoleCacheTTL(30 * time.Minute), // 用户角色关系的存活时间
    guardian.WithCacheCleanupInterval(10 * time.Minute), // 缓存清理间隔
)

// 或使用完全自定义的缓存配置
cacheConfig := storage.CacheConfig{
    EnableRoleCache:      true,
    RoleCacheTTL:         2 * time.Hour,
    EnableUserRoleCache:  true,
    UserRoleCacheTTL:     1 * time.Hour,
    CleanupInterval:      15 * time.Minute,
    MaxRoleCacheSize:     2000,  // 最多缓存2000个角色
    MaxUserRoleCacheSize: 10000, // 最多缓存10000个用户角色关系
}

g, _ := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithCacheConfig(cacheConfig),
)
```

缓存系统提供以下功能:

1. **角色缓存**: 缓存角色定义和权限，减少从存储中重复获取相同角色的开销
2. **用户角色缓存**: 缓存用户-角色关系，加速权限检查
3. **自动失效**: 当角色或权限更改时自动失效相关缓存
4. **定时清理**: 周期性清理过期条目以防止内存泄漏
5. **大小限制**: 可配置的最大缓存条目数以控制内存使用
6. **性能监控**: 内置命中率和未命中率统计

### 层次结构表示法

资源可以使用正斜杠(`/`)作为分隔符组织成层次结构:
    
```
articles/draft
articles/published
users/profiles
users/settings
```

### 通配符权限

通配符字符(`*`)可以有几种用法:

1. **操作通配符**: `"*"` 匹配特定资源的任何操作
```go
g.AddRolePermission("admin", "articles", "*")  // 管理员可以对文章执行任何操作
```

2. **资源通配符**: `"*"` 匹配特定操作的任何资源
```go
g.AddRolePermission("reviewer", "*", "read")  // 审阅者可以读取任何资源
```

3. **全局通配符**: 资源和操作都使用 `"*"` 授予完全访问权限
```go
g.AddRolePermission("superadmin", "*", "*")  // 超级管理员拥有完全访问权限
```

4. **层次通配符**: `"resource/*"` 匹配所有子资源
```go
g.AddRolePermission("editor", "articles/*", "update")  // 编辑者可以更新任何文章子资源
```

### 层次权限解析

检查层次资源路径的权限时，`Guardian` 使用以下流程:

1. 首先检查特定资源和操作的精确匹配
2. 然后检查特定资源的通配符操作(`*`)
3. 然后检查通配符资源(`*`)上的特定操作
4. 然后检查通配符资源上的通配符权限(`*`, `*`)
5. 最后遍历资源层次结构，检查带通配符的父资源

例如，检查 `"articles/draft/section"` 的 `"edit"` 操作权限:

1. 检查 `"articles/draft/section"` 的 `"edit"` 权限
2. 检查 `"articles/draft/section"` 的 `"*"` 权限
3. 检查 `"*"` 的 `"edit"` 权限
4. 检查 `"*"` 的 `"*"` 权限
5. 检查层次通配符:
  - `"articles/draft/*"` 的 `"edit"` 权限
  - `"articles/draft/*"` 的 `"*"` 权限
  - `"articles/*"` 的 `"edit"` 权限
  - `"articles/*"` 的 `"*"` 权限

这种层次解析使得高级权限自动应用于子资源而无需明确定义，从而实现高效的权限结构。

**重要**: 权限**仅**通过显式通配符模式继承。`"articles/drafts"`(无通配符)的权限将**不会**自动应用于`"articles/drafts/special"`。

**示例**:

```go
// 设置资源层次权限
g.AddRolePermission("contentManager", "content/*", "read")   // 可以读取所有内容
g.AddRolePermission("articleEditor", "content/articles/*", "edit")  // 可以编辑所有文章
g.AddRolePermission("draftEditor", "content/articles/drafts/*", "publish")  // 可以发布草稿

// 这些权限自动应用:
// - contentManager 可以读取 content/articles, content/videos 等
// - articleEditor 可以编辑 content/articles/published, content/articles/drafts 等
// - draftEditor 可以发布任何草稿文章

// 检查权限
hasPermission, _ := g.HasPermission("user123", "content/articles/drafts/article-1", "read")
// 如果 user123 有 contentManager 角色，则返回 true (因为 content/* 权限)
```

这种方法显著减少了所需的权限条目数量，同时保持对资源的精细控制。

### 中间件

`Guardian` 为 `Gin` 框架提供专用中间件函数。使用 `Guardian` 中间件时，顺序很重要:

1. **g.Auth()** 应首先应用以认证用户
2. **g.RequireRole()** 或 **g.RequirePermission()** 应在 Auth 之后应用
3. **g.RateLimit()** 可以独立应用，通常用于登录等公共端点

```go
// 正确顺序
protected := r.Group("/api")
protected.Use(g.Auth())  // 先认证
protected.Use(g.RequireRole([]string{"admin"}))  // 然后检查角色

// 对登录端点应用速率限制
r.POST("/login", g.RateLimit(), loginHandler)
```

### 上下文值

成功认证后，Guardian 的 Auth 中间件在 `Gin` 上下文中设置以下键:

```go
// 访问已认证的用户ID
userID := c.GetString(middleware.CtxKeyUserID)

// 访问用户角色(如果有)
roles := c.GetStringSlice(middleware.CtxKeyRoles)

// 访问完整解析的令牌对象
token := c.MustGet(middleware.CtxKeyToken).(*jwt.Token)
```

这些上下文值在 Auth 中间件之后执行的所有路由处理程序中都可用。这使您的 API 处理程序无需再次解析令牌即可访问用户信息。

受保护路由处理程序示例:

```go
protected.GET("/profile", func(c *gin.Context) {
    // 用户ID自动从上下文中获取
    userID := c.GetString(middleware.CtxKeyUserID)
    
    // 可以使用用户ID获取用户数据
    userData, err := userService.GetUserProfile(userID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to get user data"})
        return
    }
    
    c.JSON(200, userData)
})
```

注意，这些上下文键只在 Auth 中间件处理了带有有效令牌的请求后设置。它们在不使用 Auth 中间件的路由(如登录端点)中不可用。

## 高级配置

```go
g, _ := guardian.New(
    // 必需: JWT 签名的密钥
    guardian.WithSecretKey("your-secure-secret-key"),
    
    // 可选: 自定义存储实现
    guardian.WithStorage(myCustomStorage),
    
    // 可选: 当令牌接近过期时启用自动刷新
    guardian.WithAutoRefresh(30 * time.Minute),
    
    // 可选: 自定义令牌头名称
    guardian.WithHeaderName("X-Auth-Token"),
    
    // 可选: 设置过期令牌的清理间隔
    guardian.WithCleanupInterval(2 * time.Hour),
    
    // 可选: 启用角色和权限缓存
    guardian.WithCache(true),
    
    // 可选: 设置角色缓存过期时间
    guardian.WithRoleCacheTTL(1 * time.Hour),
    
    // 可选: 设置用户角色缓存过期时间
    guardian.WithUserRoleCacheTTL(30 * time.Minute),
    
    // 可选: 设置缓存清理间隔
    guardian.WithCacheCleanupInterval(10 * time.Minute),
)
```

### 认证中间件选项

```go
g.Auth(
    // 自定义认证头名称
    guardian.WithAuthHeaderName("X-API-Token"),
    
    // 自定义令牌类型(默认为"Bearer")
    guardian.WithAuthTokenType("Custom"),
    
    // 认证成功的回调
    guardian.OnAuthSuccess(func(c *gin.Context, token *jwt.Token) {
        // 自定义处理逻辑
    }),
    
    // 认证失败的回调
    guardian.OnAuthFailure(func(c *gin.Context, err error) {
        // 自定义处理逻辑
    }),
    
    // 自定义错误处理
    guardian.WithAuthErrorHandler(func(c *gin.Context, err error) {
        c.JSON(401, gin.H{"custom_error": err.Error()})
        c.Abort()
    }),
)
```

### 自动刷新选项

如果您在主配置中启用了自动刷新:

```go
// 在 Guardian 构造函数中启用自动刷新
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret"),
    // 启用全局自动刷新并设置默认阈值
    // 令牌的剩余有效期少于15分钟时将被刷新
    guardian.WithAutoRefresh(15 * time.Minute),
)
```

当您应用 Auth 中间件且自动刷新已启用时，刷新功能将自动包含:

```go
// 应用标准认证中间件 
router.Use(g.Auth())
```

要更精细地控制刷新行为，可以手动配置自动刷新中间件:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/middleware"
)

// 使用自定义选项应用自动刷新中间件
router.Use(middleware.AutoRefresh(
    // 令牌刷新时的回调
    guardian.OnTokenRefresh(func(c *gin.Context, oldToken, newToken string) {
        // 记录刷新事件或执行其他操作
        log.Printf("Token refreshed: %s -> %s", oldToken, newToken)
    }),
    
    // 此特定中间件实例的自定义刷新阈值
    // 覆盖 Guardian 构造函数中的全局设置
    guardian.WithRefreshThreshold(10 * time.Minute),
))
```

当令牌自动刷新时，新令牌在 HTTP 响应的 `X-New-Token` 头中返回。客户端应检查此头并在后续请求中使用新令牌。

### 权限中间件选项

```go
g.RequirePermission("articles", "edit",
    // 权限授予时的回调
    guardian.OnPermissionGranted(func(c *gin.Context, userID, resource, action string) {
        // 记录访问等
    }),
    
    // 权限拒绝时的回调
    guardian.OnPermissionDenied(func(c *gin.Context, userID, resource, action string) {
        // 记录拒绝等
    }),
    
    // 自定义错误处理
    guardian.WithPermissionErrorHandler(func(c *gin.Context, err error) {
        c.JSON(403, gin.H{"error": "No permission to access this resource"})
        c.Abort()
    }),
)
```

### 角色中间件选项

```go
g.RequireRole([]string{"admin", "editor"},
    // 角色检查通过时的回调
    guardian.OnRoleGranted(func(c *gin.Context, userID string, roles []string) {
        // 记录访问等
    }),
    
    // 角色检查失败时的回调
    guardian.OnRoleDenied(func(c *gin.Context, userID string, roles []string) {
        // 记录拒绝等
    }),
    
    // 自定义错误处理
    guardian.WithRoleErrorHandler(func(c *gin.Context, err error) {
        c.JSON(403, gin.H{"error": "Higher privileges required"})
        c.Abort()
    }),
)
```

### 速率限制中间件选项

```go
g.RateLimit(
    // 设置每分钟请求限制
    guardian.WithRateLimitRequestsPerMinute(60),
    
    // 设置并发请求的突发限制
    guardian.WithRateLimitBurst(10),
    
    // 设置速率限制条目的清理间隔
    guardian.WithRateLimitCleanupInterval(5 * time.Minute),
    
    // 设置速率限制条目的过期时间
    guardian.WithRateLimitExpirationTime(10 * time.Minute),
    
    // 自定义错误处理
    guardian.WithRateLimitErrorHandler(func(c *gin.Context, err error) {
        c.JSON(429, gin.H{"error": "Too many requests, please try again later"})
        c.Abort()
    }),
    
    // 自定义键提取器(用于识别请求源)
    guardian.WithRateLimitKeyExtractor(func(c *gin.Context) string {
        // 例如，从自定义头或JWT令牌中提取用户ID
        return c.GetHeader("X-User-ID")
    }),
    
    // 速率限制触发时的回调
    guardian.OnRateLimited(func(key string, c *gin.Context) {
        // 记录速率限制请求
    }),
    
    // 普通请求的回调(包括剩余令牌)
    guardian.OnRateLimitRequest(func(key string, remaining int, c *gin.Context) {
        // 可用于监控或添加自定义响应头
    }),
)
```

速率限制中间件在响应中添加以下头:

- `X-RateLimit-Limit`: 表示速率限制上限
- `X-RateLimit-Remaining`: 表示剩余令牌数

## 存储选项

`Guardian` 为角色、权限和用户角色映射支持多种存储后端:

### 内存存储(默认)

默认情况下，`Guardian` 使用内存存储实现，将所有数据存储在 Go 映射中:

```go
// 使用默认内存存储
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    // 未指定存储选项 - 将使用内存存储
)
```

内存存储适用于测试或不需要持久性的应用。但是，应用重启时所有数据都会丢失。

### SQL存储

对于生产系统，`Guardian` 提供基于SQL的存储实现，将角色和权限数据持久化到数据库:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/storage"
    _ "github.com/go-sql-driver/mysql" // 导入MySQL驱动
)

// 创建MySQL存储
sqlStorage, err := storage.CreateMySQLStorage(
    "user:password@tcp(127.0.0.1:3306)/guardian_db?parseTime=true"
)
if err != nil {
    log.Fatalf("Failed to create SQL storage: %v", err)
}

// 创建带SQL存储的Guardian实例
g, err := guardian.New(
    guardian.WithSecretKey("your-secure-secret-key"),
    guardian.WithStorage(sqlStorage),
)
if err != nil {
    log.Fatalf("Failed to create Guardian: %v", err)
}
defer g.Close()
```

#### 支持的数据库系统

Guardian 当前支持以下数据库系统:

1. **MySQL/MariaDB**:
   ```go
   storage, err := storage.CreateMySQLStorage(
       "user:password@tcp(127.0.0.1:3306)/dbname?parseTime=true"
   )
   ```

2. **PostgreSQL**:
   ```go
   storage, err := storage.CreatePostgresStorage(
       "host=localhost port=5432 user=postgres password=secret dbname=guardian_db sslmode=disable"
   )
   ```

3. **SQLite**:
   ```go
   storage, err := storage.CreateSQLiteStorage("path/to/database.db")
   // 或使用内存SQLite数据库
   storage, err := storage.CreateSQLiteStorage(":memory:")
   ```

#### 与GORM一起使用

如果您的应用已经使用 `GORM` 进行数据库访问，您可以将 `Guardian` 与现有数据库连接集成:

```go
import (
    "github.com/simp-lee/guardian"
    "github.com/simp-lee/guardian/storage"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// 创建GORM连接
dsn := "user:password@tcp(127.0.0.1:3306)/database?charset=utf8mb4&parseTime=True&loc=Local"
gormDB, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    log.Fatalf("Failed to connect to database: %v", err)
}

// 获取底层*sql.DB实例
sqlDB, err := gormDB.DB()
if err != nil {
    log.Fatalf("Failed to get underlying sql.DB: %v", err)
}

// 使用现有连接创建Guardian存储
guardianStorage, err := storage.NewSQLStorage(sqlDB)
if err != nil {
    log.Fatalf("Failed to create Guardian storage: %v", err)
}

// 创建Guardian实例
g, err := guardian.New(
    guardian.WithSecretKey("your-secure-key"),
    guardian.WithStorage(guardianStorage),
)
```

#### 数据库架构

使用SQL存储时，`Guardian` 自动创建以下表:

- `guardian_roles`: 存储角色定义和权限
- `guardian_user_roles`: 存储用户角色关联

表使用 `IF NOT EXISTS` 子句创建，因此不会与现有表冲突。

### 数据库驱动安装

根据您选择的数据库系统，您需要安装相应的驱动:

```bash
# MySQL驱动
go get github.com/go-sql-driver/mysql

# PostgreSQL驱动
go get github.com/lib/pq

# SQLite驱动(需要CGO)
go get github.com/mattn/go-sqlite3

# SQLite驱动(纯Go，无需CGO)
go get modernc.org/sqlite
```

### 自定义存储实现

您可以通过实现Storage接口来实现自己的存储后端:

```go
type Storage interface {
    // 角色管理
    CreateRole(role *Role) error
    GetRole(roleID string) (*Role, error)
    UpdateRole(role *Role) error
    DeleteRole(roleID string) error
    ListRoles() ([]*Role, error)

    // 用户角色管理
    AddUserRole(userID, roleID string) error
    RemoveUserRole(userID, roleID string) error
    GetUserRoles(userID string) ([]string, error)

    // 权限管理
    AddRolePermission(roleID, resource, action string) error
    RemoveRolePermission(roleID, resource string) error
    HasPermission(roleID, resource, action string) (bool, error)

    // 资源管理
    Close() error
}
```

然后将您的自定义实现与Guardian一起使用:

```go
customStorage := NewMyCustomStorage(...)
g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    guardian.WithStorage(customStorage),
)
```

## 缓存管理

`Guardian`提供了对缓存系统的完全控制，使您可以根据应用需求进行微调:

```go
// 获取缓存统计
roleHits, roleMisses, userRoleHits, userRoleMisses := g.GetCacheStats()
fmt.Printf("角色缓存: 命中率 %.2f%%\n", 
    float64(roleHits)/float64(roleHits+roleMisses)*100)
fmt.Printf("用户角色缓存: 命中率 %.2f%%\n", 
    float64(userRoleHits)/float64(userRoleHits+userRoleMisses)*100)

// 获取当前缓存大小
roleCacheSize, userRoleCacheSize := g.GetCacheSize()
fmt.Printf("缓存大小: %d个角色, %d个用户角色条目\n", 
    roleCacheSize, userRoleCacheSize)

// 清除所有缓存(例如，在大规模权限更改后)
g.ClearCache()
```

调整缓存配置以平衡内存使用和性能:

```go
// 自定义缓存配置，适用于具有许多用户但角色较少的大型应用
config := storage.CacheConfig{
    EnableRoleCache:      true,
    RoleCacheTTL:         4 * time.Hour,  // 角色不常变，可以缓存更长时间
    EnableUserRoleCache:  true,
    UserRoleCacheTTL:     30 * time.Minute,
    CleanupInterval:      10 * time.Minute,
    MaxRoleCacheSize:     500,    // 系统中角色较少，适当限制
    MaxUserRoleCacheSize: 100000, // 大量用户，需要更大的缓存
}

g, _ := guardian.New(
    guardian.WithSecretKey("your-secret-key"),
    guardian.WithCacheConfig(config),
)
```

## 错误处理

`Guardian` 提供了几种可以检查和处理的错误类型:

### JWT 错误
```go
jwt.ErrMissingSecretKey  // 未提供密钥
jwt.ErrEmptyUserID       // 用户ID为空
jwt.ErrTokenCreation     // 创建令牌失败
jwt.ErrInvalidToken      // 令牌无效
jwt.ErrExpiredToken      // 令牌已过期
jwt.ErrRevokedToken      // 令牌已撤销
```

### RBAC 错误
```go
rbac.ErrInvalidRoleID             // 角色ID无效或为空
rbac.ErrEmptyUserID               // 用户ID为空
rbac.ErrInvalidResource           // 资源名称无效
rbac.ErrInvalidAction             // 操作名称无效
rbac.ErrPermissionAlreadyExists   // 角色已存在权限
```

### 中间件错误
```go
middleware.ErrUnauthorized        // 用户未认证
middleware.ErrForbidden           // 用户已认证但未授权
middleware.ErrTooManyRequests     // 用户超过速率限制
middleware.ErrUserDoesNotHaveRole // 用户没有所需角色
middleware.ErrInvalidResource     // 资源名称为空
middleware.ErrInvalidAction       // 操作名称为空
```

### 存储错误
```go
storage.ErrRoleNotFound        // 未找到角色
storage.ErrRoleAlreadyExists   // 角色已存在
storage.ErrUserAlreadyHasRole  // 用户已拥有角色
storage.ErrUserDoesNotHaveRole // 用户没有角色
storage.ErrPermissionNotFound  // 权限未找到
```

## 安全最佳实践

1. **使用强密钥**并安全管理它们(环境变量、密钥管理)
2. **保持令牌生命周期短** - 尽可能使用小时而非天
3. **在用户更改密码或安全事件期间撤销令牌**
4. **对认证端点应用速率限制**
5. **所有生产部署使用HTTPS**
6. **分配权限时遵循最小权限原则**
7. **定期审计**角色分配和权限
8. **处理令牌刷新** - 客户端应监控X-New-Token头并更新存储的令牌

## 完整API参考

完整的API参考，请参阅[godoc文档](https://pkg.go.dev/github.com/simp-lee/guardian)。

## 许可证

MIT许可证