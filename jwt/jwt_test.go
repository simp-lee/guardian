package jwt

import (
	"strings"
	"testing"
	"time"
)

func NewJWTService(secretKey string, cleanupInterval time.Duration) Service {
	config := &Config{
		SecretKey:       secretKey,
		CleanupInterval: cleanupInterval,
	}
	service, err := New(config)
	if err != nil {
		panic(err) // 仅在测试中使用
	}
	return service
}

func TestJWTServiceGenerateToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Test token generation
	tokenString, err := service.GenerateToken("test-user", []string{"user", "admin"}, time.Hour)
	if err != nil {
		t.Fatalf("Expected to generate token successfully, but got error: %v", err)
	}
	if tokenString == "" {
		t.Fatal("Expected token string to be non-empty")
	}

	// Verify token format
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		t.Fatalf("Expected JWT token to have 3 parts, but got: %d", len(parts))
	}
}

func TestJWTServiceValidateToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate token
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Validate token
	token, err := service.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("Expected token validation to succeed, but got error: %v", err)
	}

	// Check token information
	if token.UserID != "test-user" {
		t.Errorf("Expected user ID to be 'test-user', but got: '%s'", token.UserID)
	}
	if len(token.Roles) != 1 || token.Roles[0] != "user" {
		t.Errorf("Expected roles to be ['user'], but got: %v", token.Roles)
	}
}

func TestJWTServiceRefreshToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate token
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Refresh token
	refreshedToken, err := service.RefreshToken(tokenString)
	if err != nil {
		t.Fatalf("Expected token refresh to succeed, but got error: %v", err)
	}

	// Validate new token
	token, err := service.ValidateToken(refreshedToken)
	if err != nil {
		t.Fatalf("Expected refreshed token validation to succeed, but got error: %v", err)
	}

	if token.UserID != "test-user" {
		t.Errorf("After refresh expected user ID to be 'test-user', but got: '%s'", token.UserID)
	}
}

func TestJWTServiceRevokeToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate token
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Revoke token
	err := service.RevokeToken(tokenString)
	if err != nil {
		t.Fatalf("Expected token revocation to succeed, but got error: %v", err)
	}

	// Validation of revoked token should fail
	_, err = service.ValidateToken(tokenString)
	if err != ErrRevokedToken {
		t.Fatalf("Expected validation of revoked token to fail with ErrRevokedToken, but got error: %v", err)
	}
}

func TestJWTServiceRevokeAllUserTokens(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate tokens
	tokenString1, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)
	tokenString2, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Revoke all tokens
	err := service.RevokeAllUserTokens("test-user")
	if err != nil {
		t.Fatalf("Expected revocation of all tokens to succeed, but got error: %v", err)
	}

	// Both tokens should fail validation
	_, err1 := service.ValidateToken(tokenString1)
	_, err2 := service.ValidateToken(tokenString2)

	if err1 != ErrRevokedToken || err2 != ErrRevokedToken {
		t.Fatalf("Expected all tokens to fail validation with ErrRevokedToken, but got errors: %v and %v", err1, err2)
	}
}

func TestJWTServiceInvalidToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Validate invalid token
	_, err := service.ValidateToken("invalid.token.string")
	if err != ErrInvalidToken {
		t.Fatalf("Expected invalid token validation to fail with ErrInvalidToken, but got error: %v", err)
	}
}

func TestJWTServiceExpiredToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate a token that expires quickly
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Millisecond*50)

	// Wait for token to expire
	time.Sleep(time.Millisecond * 100)

	// Validate expired token
	_, err := service.ValidateToken(tokenString)
	if err != ErrExpiredToken {
		t.Fatalf("Expected expired token validation to fail with ErrExpiredToken, but got error: %v", err)
	}
}

func TestJWTServiceCleanupRevokedTokens(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Millisecond*100)
	jwtService, ok := service.(*jwtService)
	if !ok {
		t.Fatal("Could not convert to jwtService type")
	}

	// Generate token and revoke
	tokenString, err := service.GenerateToken("test-user", []string{"user"}, time.Millisecond*50)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	token, err := service.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	err = service.RevokeToken(tokenString)
	if err != nil {
		t.Fatalf("Error revoking token: %v", err)
	}

	// Verify token is in revoked list
	jwtService.mu.RLock()
	_, exists := jwtService.revokedTokens[token.TokenID]
	jwtService.mu.RUnlock()

	if !exists {
		t.Fatal("Expected token to be in revoked list")
	}

	// Wait for expiration and cleanup
	time.Sleep(time.Millisecond * 200)

	// Verify token has been removed from revoked list
	jwtService.mu.RLock()
	_, exists = jwtService.revokedTokens[token.TokenID]
	jwtService.mu.RUnlock()

	if exists {
		t.Fatal("Expected token to be removed from revoked list")
	}
}

func TestJWTServiceWithWrongSecretKey(t *testing.T) {
	service1 := NewJWTService("secret-key-1", time.Second*5)
	service2 := NewJWTService("secret-key-2", time.Second*5)
	defer service1.Close()
	defer service2.Close()

	// Generate token with service1
	tokenString, _ := service1.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Validate with service2 (should fail due to different secret keys)
	_, err := service2.ValidateToken(tokenString)
	if err != ErrInvalidToken {
		t.Fatalf("Expected validation with different secret key to fail with ErrInvalidToken, but got error: %v", err)
	}
}

func TestJWTServiceEmptyUserID(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Try to generate a token with empty user ID
	_, err := service.GenerateToken("", []string{"user"}, time.Hour)
	if err != ErrEmptyUserID {
		t.Fatalf("Expected token generation with empty user ID to fail with ErrEmptyUserID, but got error: %v", err)
	}

	// Try to revoke all tokens with empty user ID
	err = service.RevokeAllUserTokens("")
	if err != ErrEmptyUserID {
		t.Fatalf("Expected revocation of tokens for empty user ID to fail with ErrEmptyUserID, but got error: %v", err)
	}
}

func TestJWTServiceEmptyRoles(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Test generating a token with no roles
	tokenString, err := service.GenerateToken("test-user", []string{}, time.Hour)
	if err != nil {
		t.Fatalf("Expected to generate token with empty roles successfully, but got error: %v", err)
	}

	// Validate token
	token, err := service.ValidateToken(tokenString)
	if err != nil {
		t.Fatalf("Expected token validation to succeed, but got error: %v", err)
	}

	if len(token.Roles) != 0 {
		t.Errorf("Expected roles list to be empty, but got: %v", token.Roles)
	}
}

func TestJWTServiceMalformedToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Test malformed token
	_, err := service.ValidateToken("header.payload")
	if err != ErrInvalidToken {
		t.Fatalf("Expected malformed token validation to fail with ErrInvalidToken, but got error: %v", err)
	}

	// Test token with only one part
	_, err = service.ValidateToken("header")
	if err != ErrInvalidToken {
		t.Fatalf("Expected incomplete token validation to fail with ErrInvalidToken, but got error: %v", err)
	}
}

func TestJWTServiceParseToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate token
	tokenString, _ := service.GenerateToken("test-user", []string{"user", "admin"}, time.Hour)

	// Parse token
	token, err := service.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("Expected token parsing to succeed, but got error: %v", err)
	}

	// Check token information
	if token.UserID != "test-user" {
		t.Errorf("Expected user ID to be 'test-user', but got: '%s'", token.UserID)
	}
	if len(token.Roles) != 2 || token.Roles[0] != "user" || token.Roles[1] != "admin" {
		t.Errorf("Expected roles to be ['user', 'admin'], but got: %v", token.Roles)
	}
}

func TestJWTServiceIsTokenRevoked(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	jwtService, ok := service.(*jwtService)
	if !ok {
		t.Fatal("Could not convert to jwtService type")
	}
	defer service.Close()

	// Generate token
	tokenString, err := service.GenerateToken("test-user", []string{"user"}, time.Hour)
	if err != nil {
		t.Fatalf("Error generating token: %v", err)
	}

	token, err := service.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("Error parsing token: %v", err)
	}

	// Check non-revoked token
	if jwtService.IsTokenRevoked(token.TokenID) {
		t.Fatal("Expected token to not be revoked, but IsTokenRevoked returned true")
	}

	// Revoke token
	service.RevokeToken(tokenString)

	// Check revoked token
	if !jwtService.IsTokenRevoked(token.TokenID) {
		t.Fatal("Expected token to be revoked, but IsTokenRevoked returned false")
	}

	// Test empty tokenID
	if jwtService.IsTokenRevoked("") {
		t.Fatal("Expected empty tokenID to return false, but got true")
	}
}

func TestJWTServiceCleanupRevokedUsers(t *testing.T) {
	// Use very short cleanup interval to ensure cleanup happens during test
	service := NewJWTService("test-secret-key", time.Millisecond*50)
	jwtService, ok := service.(*jwtService)
	if !ok {
		t.Fatal("Could not convert to jwtService type")
	}
	defer service.Close()

	// Revoke user tokens
	service.RevokeAllUserTokens("test-user")

	// Verify user is in revoked list
	jwtService.mu.RLock()
	_, exists := jwtService.revokedUsers["test-user"]
	jwtService.mu.RUnlock()

	if !exists {
		t.Fatal("Expected user to be in revoked list")
	}

	// Modify revocation time to be two months ago
	jwtService.mu.Lock()
	jwtService.revokedUsers["test-user"] = time.Now().AddDate(0, -2, 0)
	jwtService.mu.Unlock()

	// Wait for cleanup
	time.Sleep(time.Millisecond * 100)

	// Verify user has been removed from revoked list
	jwtService.mu.RLock()
	_, exists = jwtService.revokedUsers["test-user"]
	jwtService.mu.RUnlock()

	if exists {
		t.Fatal("Expected user to be removed from revoked list")
	}
}

func TestJWTServiceTokenIDGeneration(t *testing.T) {
	// Test uniqueness of generated token IDs
	tokenIDs := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateTokenID()
		if err != nil {
			t.Fatalf("Failed to generate token ID: %v", err)
		}
		if tokenIDs[id] {
			t.Fatal("Generated duplicate token ID")
		}
		tokenIDs[id] = true
	}
}

func TestJWTServiceRefreshExpiredToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate a token that will expire quickly
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Millisecond*50)

	// Wait for token to expire
	time.Sleep(time.Millisecond * 100)

	// Try to refresh expired token
	_, err := service.RefreshToken(tokenString)
	if err != ErrExpiredToken {
		t.Fatalf("Expected refreshing expired token to return ErrExpiredToken, but got error: %v", err)
	}
}

func TestJWTServiceRefreshRevokedToken(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	defer service.Close()

	// Generate token
	tokenString, _ := service.GenerateToken("test-user", []string{"user"}, time.Hour)

	// Revoke token
	service.RevokeToken(tokenString)

	// Try to refresh revoked token
	_, err := service.RefreshToken(tokenString)
	if err != ErrRevokedToken {
		t.Fatalf("Expected refreshing revoked token to return ErrRevokedToken, but got error: %v", err)
	}
}

func TestJWTServiceNilCleanupCancel(t *testing.T) {
	service := NewJWTService("test-secret-key", time.Second*5)
	jwtService, ok := service.(*jwtService)
	if !ok {
		t.Fatal("Could not convert to jwtService type")
	}

	// Manually set cleanupCancel to nil
	jwtService.cleanupCancel = nil

	// Close should not panic
	service.Close()
}

func TestJWTServiceConfigErrors(t *testing.T) {
	// Test empty secret key
	_, err := New(&Config{
		SecretKey:       "",
		CleanupInterval: time.Second,
	})
	if err != ErrMissingSecretKey {
		t.Fatalf("Expected ErrMissingSecretKey for empty secret key, got: %v", err)
	}

	// Test zero cleanup interval
	service, err := New(&Config{
		SecretKey:       "test-key",
		CleanupInterval: 0, // zero interval
	})
	if err != nil {
		t.Fatalf("Expected successful creation with default cleanup interval, got: %v", err)
	}
	defer service.Close()
}
