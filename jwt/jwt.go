package jwt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// jwtService implements the Service interface using JWT.
type jwtService struct {
	secretKey     []byte
	revokedTokens map[string]time.Time // tokenID -> expiresAt
	revokedUsers  map[string]time.Time // userID -> revokedAt
	mu            sync.RWMutex

	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
}

type jwtClaims struct {
	UserID  string   `json:"user_id"`
	Roles   []string `json:"roles"`
	TokenID string   `json:"token_id"`
	jwtlib.RegisteredClaims
}

// newJWTService creates a new TokenService implemented with JWT.
func newJWTService(config *Config) Service {
	ctx, cancel := context.WithCancel(context.Background())

	service := &jwtService{
		secretKey:     []byte(config.SecretKey),
		revokedTokens: make(map[string]time.Time),
		revokedUsers:  make(map[string]time.Time),
		cleanupCtx:    ctx,
		cleanupCancel: cancel,
	}

	// Cleanup revoked tokens with context cancellation support
	go func() {
		ticker := time.NewTicker(config.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				service.cleanupRevokedTokens()
			case <-ctx.Done():
				return
			}
		}
	}()

	return service
}

func (s *jwtService) Close() {
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
}

func generateTokenID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (s *jwtService) GenerateToken(userID string, roles []string, expiresIn time.Duration) (string, error) {
	if userID == "" {
		return "", ErrEmptyUserID
	}

	tokenID, err := generateTokenID()
	if err != nil {
		return "", ErrTokenCreation
	}

	now := time.Now()
	expiresAt := now.Add(expiresIn)

	claims := jwtClaims{
		UserID:  userID,
		Roles:   roles,
		TokenID: tokenID,
		RegisteredClaims: jwtlib.RegisteredClaims{
			ExpiresAt: jwtlib.NewNumericDate(expiresAt),
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
		},
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", ErrTokenCreation
	}

	return tokenString, nil
}

func (s *jwtService) ValidateToken(tokenString string) (*Token, error) {
	token, err := s.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if time.Now().After(token.ExpiresAt) {
		return nil, ErrExpiredToken
	}

	s.mu.RLock()
	_, tokenRevoked := s.revokedTokens[token.TokenID]
	userRevokedTime, userRevoked := s.revokedUsers[token.UserID]
	s.mu.RUnlock()

	if tokenRevoked {
		return nil, ErrRevokedToken
	}

	if userRevoked && userRevokedTime.After(token.IssuedAt) {
		return nil, ErrRevokedToken
	}

	return token, nil
}

func (s *jwtService) RefreshToken(tokenString string) (string, error) {
	oldToken, err := s.ParseToken(tokenString)
	if err != nil {
		return "", err
	}

	// Check if the token has been revoked
	s.mu.RLock()
	_, tokenRevoked := s.revokedTokens[oldToken.TokenID]
	userRevokedTime, userRevoked := s.revokedUsers[oldToken.UserID]
	s.mu.RUnlock()

	if tokenRevoked {
		return "", ErrRevokedToken
	}

	if userRevoked && userRevokedTime.After(oldToken.IssuedAt) {
		return "", ErrRevokedToken
	}

	// Check if the token has expired
	if time.Now().After(oldToken.ExpiresAt) {
		return "", ErrExpiredToken
	}

	// Revoke the old token
	s.mu.Lock()
	s.revokedTokens[oldToken.TokenID] = oldToken.ExpiresAt
	s.mu.Unlock()

	// Calculate the new token's expiration time based on the old token's duration
	expiresIn := oldToken.ExpiresAt.Sub(oldToken.IssuedAt)

	// Generate a new token with the same claims but extended duration
	return s.GenerateToken(oldToken.UserID, oldToken.Roles, expiresIn)
}

// ParseToken parses a token without validating it.
func (s *jwtService) ParseToken(tokenString string) (*Token, error) {
	token, err := jwtlib.ParseWithClaims(tokenString, &jwtClaims{}, func(token *jwtlib.Token) (any, error) {
		if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		if token.Method.Alg() != jwtlib.SigningMethodHS256.Alg() {
			return nil, ErrInvalidToken
		}
		return s.secretKey, nil
	})

	if err != nil {
		// Check if the token has expired
		if errors.Is(err, jwtlib.ErrTokenExpired) {
			if token != nil {
				if claims, ok := token.Claims.(*jwtClaims); ok {
					return &Token{
						UserID:    claims.UserID,
						Roles:     claims.Roles,
						ExpiresAt: claims.ExpiresAt.Time,
						IssuedAt:  claims.IssuedAt.Time,
						TokenID:   claims.TokenID,
					}, nil
				}
			}
		}
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(*jwtClaims); ok && token.Valid {
		return &Token{
			UserID:    claims.UserID,
			Roles:     claims.Roles,
			ExpiresAt: claims.ExpiresAt.Time,
			IssuedAt:  claims.IssuedAt.Time,
			TokenID:   claims.TokenID,
		}, nil
	}

	return nil, ErrInvalidToken
}

func (s *jwtService) RevokeToken(tokenString string) error {
	token, err := s.ParseToken(tokenString)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Add the token to the list of revoked tokens, using the token ID as the key
	s.revokedTokens[token.TokenID] = token.ExpiresAt

	return nil
}

func (s *jwtService) RevokeAllUserTokens(userID string) error {
	if userID == "" {
		return ErrEmptyUserID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.revokedUsers[userID] = time.Now()
	return nil
}

func (s *jwtService) IsTokenRevoked(tokenID string) bool {
	if tokenID == "" {
		return false
	}

	s.mu.RLock()
	_, revoked := s.revokedTokens[tokenID]
	s.mu.RUnlock()

	return revoked
}

func (s *jwtService) cleanupRevokedTokens() {
	now := time.Now()

	// Remains a month of user revocation records
	threshold := now.AddDate(0, -1, 0)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove expired tokens
	for tokenID, expiresAt := range s.revokedTokens {
		if now.After(expiresAt) {
			delete(s.revokedTokens, tokenID)
		}
	}

	// Remove revoked users that have been revoked more than a month ago
	for userID, revokedAt := range s.revokedUsers {
		if revokedAt.Before(threshold) {
			delete(s.revokedUsers, userID)
		}
	}
}
