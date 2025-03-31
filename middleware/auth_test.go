package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestAuthMiddlewareValidToken tests the auth middleware with a valid token
func TestAuthMiddlewareValidToken(t *testing.T) {
	// Create a mock token service
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
	}

	// Create a new router with the auth middleware
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// Add a test route
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get(CtxKeyUserID)
		roles, _ := c.Get(CtxKeyRoles)
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "roles": roles})
	})

	// Create a test request with a valid token
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, w.Code)
	}

	// Verify the response body contains the user ID
	if !strings.Contains(w.Body.String(), "test-user") {
		t.Errorf("Response body does not contain user ID: %s", w.Body.String())
	}
}

// TestAuthMiddlewareInvalidToken tests the auth middleware with an invalid token
func TestAuthMiddlewareInvalidToken(t *testing.T) {
	// Create a mock token service
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, ErrInvalidToken
		},
	}

	// Create a new router with the auth middleware
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// Add a test route that should not be reached
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test cases for invalid tokens
	testCases := []struct {
		name          string
		authHeader    string
		expectedCode  int
		expectedError string
	}{
		{
			name:          "No Authorization Header",
			authHeader:    "",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "unauthorized",
		},
		{
			name:          "Invalid Authorization Format",
			authHeader:    "InvalidFormat",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "invalid token",
		},
		{
			name:          "Wrong Token Type",
			authHeader:    "Basic invalid-token",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "invalid token",
		},
		{
			name:          "invalid Token",
			authHeader:    "Bearer invalid-token",
			expectedCode:  http.StatusUnauthorized,
			expectedError: "invalid token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/test", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.expectedCode {
				t.Errorf("Expected status code %d but got %d", tc.expectedCode, w.Code)
			}

			if !strings.Contains(w.Body.String(), tc.expectedError) {
				t.Errorf("Expected error message '%s' but got '%s'", tc.expectedError, w.Body.String())
			}
		})
	}
}

func TestAuthMiddlewareInvalidToken2(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, ErrInvalidToken
		},
	}

	// 跟踪回调函数是否被调用
	failureCalled := false

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		OnFailure: func(c *gin.Context, err error) {
			failureCalled = true
		},
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有无效令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusUnauthorized, w.Code)
	}

	// 验证失败回调函数被调用
	if !failureCalled {
		t.Error("OnFailure回调未被调用")
	}
}

// TestAuthMiddlewareExpiredToken tests the auth middleware with an expired token
func TestAuthMiddlewareExpiredToken(t *testing.T) {
	// Create a mock token service
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "expired-token" {
				return nil, ErrExpiredToken
			}
			return nil, ErrInvalidToken
		},
	}

	// Create a new router with the auth middleware
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// Add a test route
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request with an expired token
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d but got %d", http.StatusUnauthorized, w.Code)
	}

	if !strings.Contains(w.Body.String(), "token has expired") {
		t.Errorf("Expected error message 'token has expired' but got '%s'", w.Body.String())
	}
}

// TestAuthMiddlewareRevokedToken tests the auth middleware with a revoked token
func TestAuthMiddlewareRevokedToken(t *testing.T) {
	// Create a mock token service
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "revoked-token" {
				return nil, ErrRevokedToken
			}
			return nil, ErrInvalidToken
		},
	}

	// Create a new router with the auth middleware
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// Add a test route
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Create a test request with a revoked token
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer revoked-token")
	w := httptest.NewRecorder()

	// Process the request
	router.ServeHTTP(w, req)

	// Verify the response
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d but got %d", http.StatusUnauthorized, w.Code)
	}

	if !strings.Contains(w.Body.String(), "token has been revoked") {
		t.Errorf("Expected error message 'token has been revoked' but got '%s'", w.Body.String())
	}
}

// TestAuthMiddlewareCustomOptions tests the auth middleware with custom options
func TestAuthMiddlewareCustomOptions(t *testing.T) {
	// Create a mock token service
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
	}

	// Create a custom error handler
	customErrorsCalled := 0
	customErrorHandler := func(c *gin.Context, err error) {
		customErrorsCalled++
		c.JSON(http.StatusTeapot, gin.H{"custom_error": err.Error()})
		c.Abort()
	}

	// Create a new router with the auth middleware and custom options
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		HeaderName:   "X-Auth-Token",
		TokenType:    "CustomType",
		ErrorHandler: customErrorHandler,
	}))

	// Add a test route
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Test case 1: Valid token with custom header and type
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Auth-Token", "CustomType valid-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d but got %d", http.StatusOK, w.Code)
	}

	// Test case 2: Invalid token with custom error handler
	req, _ = http.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Auth-Token", "CustomType invalid-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTeapot {
		t.Errorf("Expected status code %d but got %d", http.StatusTeapot, w.Code)
	}

	if !strings.Contains(w.Body.String(), "custom_error") {
		t.Errorf("Expected custom error format but got '%s'", w.Body.String())
	}

	if customErrorsCalled != 1 {
		t.Errorf("Expected custom error handler to be called once but was called %d times", customErrorsCalled)
	}
}

func TestAuthMiddlewareMissingToken(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, nil // 不应该被调用
		},
	}

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建没有Authorization头的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddlewareWrongTokenType(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, nil // 不应该被调用
		},
	}

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		TokenType:    "Bearer", // 期望Bearer前缀
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有错误令牌类型的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic valid-token") // 使用Basic而不是Bearer
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddlewareCustomHeaderName(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {

			// 打印接收到的令牌以进行调试
			t.Logf("收到验证请求的令牌: '%s'", tokenString)

			// 接受任何令牌值用于测试
			return &Token{
				UserID: "test-user",
				Roles:  []string{"admin"},
			}, nil
		},
	}

	// 创建一个带有自定义头名称的auth中间件
	// 注意：我们不设置TokenType，让它使用默认值"Bearer"
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		HeaderName:   "X-API-Token",
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get(CtxKeyUserID)
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	// 创建带有自定义头的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	// 包含"Bearer "前缀，因为当前auth.go实现会要求此前缀
	req.Header.Set("X-API-Token", "Bearer valid-token")

	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
	}

	// 验证响应体包含用户ID
	if !strings.Contains(w.Body.String(), "test-user") {
		t.Errorf("响应体不包含用户ID: %s", w.Body.String())
	}
}

func TestAuthMiddlewareExpiredToken2(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, ErrExpiredToken
		},
	}

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有过期令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusUnauthorized, w.Code)
	}

	// 验证响应体包含expired字样
	if !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("响应体不包含'expired'词: %s", w.Body.String())
	}
}

func TestAuthMiddlewareRevokedToken2(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, ErrRevokedToken
		},
	}

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有已吊销令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer revoked-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusUnauthorized {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusUnauthorized, w.Code)
	}

	// 验证响应体包含revoked字样
	if !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("响应体不包含'revoked'词: %s", w.Body.String())
	}
}

func TestAuthMiddlewareWithDefaultOptions(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
	}

	// 从默认选项创建
	opts := DefaultAuthOptions()
	opts.TokenService = mockService

	// 创建一个带有auth中间件的新路由器
	router := setupRouter()
	router.Use(Auth(opts))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get(CtxKeyUserID)
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	// 创建带有有效令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
	}

	// 验证响应体包含用户ID
	if !strings.Contains(w.Body.String(), "test-user") {
		t.Errorf("响应体不包含用户ID: %s", w.Body.String())
	}
}

func TestAuthMiddlewareSuccessCallback(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
	}

	// 跟踪回调函数是否被调用
	successCalled := false
	var capturedToken *Token

	// 创建一个带有自定义成功回调的auth中间件
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		OnSuccess: func(c *gin.Context, token *Token) {
			successCalled = true
			capturedToken = token
		},
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有有效令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证成功回调函数被调用
	if !successCalled {
		t.Error("OnSuccess回调未被调用")
	}

	// 验证捕获的令牌信息正确
	if capturedToken == nil || capturedToken.UserID != "test-user" {
		t.Errorf("捕获的令牌信息不正确: %+v", capturedToken)
	}
}

func TestAuthMiddlewareCustomErrorHandler(t *testing.T) {
	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return nil, ErrInvalidToken
		},
	}

	// 跟踪自定义错误处理器是否被调用
	errorHandlerCalled := false

	// 创建一个带有自定义错误处理器的auth中间件
	router := setupRouter()
	router.Use(Auth(AuthOptions{
		TokenService: mockService,
		ErrorHandler: func(c *gin.Context, err error) {
			errorHandlerCalled = true
			c.JSON(http.StatusBadRequest, gin.H{"custom_error": err.Error()})
			c.Abort()
		},
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建带有无效令牌的测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证自定义错误处理器被调用
	if !errorHandlerCalled {
		t.Error("自定义错误处理器未被调用")
	}

	// 验证响应状态码为自定义值
	if w.Code != http.StatusBadRequest {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusBadRequest, w.Code)
	}

	// 验证响应体使用了自定义字段
	if !strings.Contains(w.Body.String(), "custom_error") {
		t.Errorf("响应体不包含自定义错误字段: %s", w.Body.String())
	}
}
