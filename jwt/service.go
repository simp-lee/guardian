package jwt

import (
	"errors"
	"time"
)

// Token represents a parsed JWT token with its claims.
type Token struct {
	UserID    string
	Roles     []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	TokenID   string
}

// Service defines the interface for JWT token management operations.
type Service interface {
	// GenerateToken creates a new JWT token for the given user ID and roles.
	GenerateToken(userID string, roles []string, expiresIn time.Duration) (string, error)

	// ValidateToken validates a token string and returns the parsed token.
	ValidateToken(tokenString string) (*Token, error)

	// RefreshToken invalidates the old token and generates a new one with the same claims.
	RefreshToken(tokenString string) (string, error)

	// RevokeToken adds a token to the revocation list.
	RevokeToken(tokenString string) error

	// IsTokenRevoked checks if a token is in the revocation list.
	IsTokenRevoked(tokenID string) bool

	// ParseToken parses a token without fully validating it.
	ParseToken(tokenString string) (*Token, error)

	// RevokeAllUserTokens revokes all tokens for a specific user.
	RevokeAllUserTokens(userID string) error

	// Close terminates any background processes of the service.
	Close()
}

var (
	ErrMissingSecretKey = errors.New("jwt: missing secret key")
	ErrEmptyUserID      = errors.New("jwt: empty user ID")
	ErrTokenCreation    = errors.New("jwt: failed to create token")
	ErrInvalidToken     = errors.New("jwt: invalid token")
	ErrExpiredToken     = errors.New("jwt: token has expired")
	ErrRevokedToken     = errors.New("jwt: token has been revoked")
)

// Config contains settings for the JWT service.
type Config struct {
	SecretKey       string        // Secret key used for signing tokens
	CleanupInterval time.Duration // Interval for cleaning up expired tokens
}

// New creates a new JWT service with the provided configuration.
func New(config *Config) (Service, error) {
	// Validate the configuration
	if config.SecretKey == "" {
		return nil, ErrMissingSecretKey
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = 1 * time.Hour
	}

	return newJWTService(config), nil
}
