package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/jwt"
)

// AuthOptions defines configuration options for the authentication middleware.
type AuthOptions struct {
	TokenService jwt.Service
	HeaderName   string
	TokenType    string // 如果为空，则不使用令牌类型前缀
	ErrorHandler func(*gin.Context, error)
	OnSuccess    func(*gin.Context, *jwt.Token)
	OnFailure    func(*gin.Context, error)
}

// DefaultAuthOptions returns the default options for the authentication middleware.
func DefaultAuthOptions() AuthOptions {
	return AuthOptions{
		HeaderName:   "Authorization",
		TokenType:    "Bearer",
		ErrorHandler: DefaultAuthErrorHandler,
		OnSuccess:    func(*gin.Context, *jwt.Token) {},
		OnFailure:    func(*gin.Context, error) {},
	}
}

// Auth is a Gin middleware that authenticates requests using JWT tokens.
// It reads the token from the Authorization header, validates it using the provided
// TokenService, and sets the user ID and token in the request context.
func Auth(opts AuthOptions) gin.HandlerFunc {
	headerName := opts.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	tokenType := opts.TokenType
	if tokenType == "" {
		tokenType = "Bearer"
	}

	handleError := opts.ErrorHandler
	if handleError == nil {
		handleError = DefaultAuthErrorHandler
	}

	onSuccess := opts.OnSuccess
	if onSuccess == nil {
		onSuccess = func(c *gin.Context, token *jwt.Token) {}
	}

	onFailure := opts.OnFailure
	if onFailure == nil {
		onFailure = func(c *gin.Context, err error) {}
	}

	return func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader(headerName)
		if authHeader == "" {
			onFailure(c, ErrUnauthorized)
			handleError(c, ErrUnauthorized)
			return
		}

		// Check token type prefix
		tokenString := authHeader
		if tokenType != "" {
			prefix := tokenType + " "
			if !strings.HasPrefix(authHeader, prefix) {
				onFailure(c, jwt.ErrInvalidToken)
				handleError(c, jwt.ErrInvalidToken)
				return
			}
			tokenString = authHeader[len(prefix):]
		}

		// Validate token
		token, err := opts.TokenService.ValidateToken(tokenString)
		if err != nil {
			onFailure(c, err)
			handleError(c, err)
			return
		}

		onSuccess(c, token)

		// Set token data in context
		c.Set(CtxKeyUserID, token.UserID)
		if len(token.Roles) > 0 {
			c.Set(CtxKeyRoles, token.Roles)
		}
		c.Set(CtxKeyToken, token)

		c.Next()
	}
}
