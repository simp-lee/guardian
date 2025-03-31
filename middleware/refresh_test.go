package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestAutoRefreshMiddleware(t *testing.T) {
	// 创建即将过期的令牌（5分钟后过期）
	expiringToken := &Token{
		UserID:    "test-user",
		Roles:     []string{"admin"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// 创建不会很快过期的令牌（30分钟后过期）
	notExpiringToken := &Token{
		UserID:    "test-user",
		Roles:     []string{"admin"},
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "expiring-token" {
				return expiringToken, nil
			} else if tokenString == "not-expiring-token" {
				return notExpiringToken, nil
			}
			return nil, ErrInvalidToken
		},
		refreshFunc: func(tokenString string) (string, error) {
			if tokenString == "expiring-token" {
				return "refreshed-token", nil
			}
			return "", ErrInvalidToken
		},
		parseFunc: func(tokenString string) (*Token, error) {
			if tokenString == "expiring-token" {
				return expiringToken, nil
			} else if tokenString == "not-expiring-token" {
				return notExpiringToken, nil
			}
			return nil, ErrInvalidToken
		},
	}

	t.Run("刷新临近过期的令牌", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false
		var oldToken, newToken string

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			RefreshThreshold: 10 * time.Minute, // 10分钟阈值，令牌将在5分钟后过期
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
				oldToken = old
				newToken = new
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调被调用
		if !refreshCalled {
			t.Error("期望调用OnRefresh回调，但未被调用")
		}

		// 验证令牌值正确
		if oldToken != "expiring-token" {
			t.Errorf("期望旧令牌为 'expiring-token' 但得到 '%s'", oldToken)
		}
		if newToken != "refreshed-token" {
			t.Errorf("期望新令牌为 'refreshed-token' 但得到 '%s'", newToken)
		}

		// 验证响应头中包含新令牌
		if w.Header().Get("X-New-Token") != "refreshed-token" {
			t.Errorf("期望响应头X-New-Token为 'refreshed-token' 但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("不刷新未临近过期的令牌", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := notExpiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			RefreshThreshold: 10 * time.Minute, // 10分钟阈值，令牌将在30分钟后过期
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer not-expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("跳过错误响应的刷新", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加返回错误的测试路由
		router.GET("/error", func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/error", nil)
		req.Header.Set("Authorization", "Bearer expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusBadRequest {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusBadRequest, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("上下文中没有令牌", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("刷新令牌错误", func(t *testing.T) {
		// 创建模拟令牌服务，刷新时返回错误
		errorMockService := &mockTokenService{
			validateFunc: func(tokenString string) (*Token, error) {
				return expiringToken, nil
			},
			refreshFunc: func(tokenString string) (string, error) {
				return "", ErrInvalidToken
			},
			parseFunc: func(tokenString string) (*Token, error) {
				return expiringToken, nil
			},
		}

		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     errorMockService,
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("使用自定义头名称", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false
		var oldToken, newToken string

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			HeaderName:       "X-API-Token",
			TokenType:        "Custom",
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
				oldToken = old
				newToken = new
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Token", "Custom expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调被调用
		if !refreshCalled {
			t.Error("期望调用OnRefresh回调，但未被调用")
		}

		// 验证令牌值正确
		if oldToken != "expiring-token" {
			t.Errorf("期望旧令牌为 'expiring-token' 但得到 '%s'", oldToken)
		}
		if newToken != "refreshed-token" {
			t.Errorf("期望新令牌为 'refreshed-token' 但得到 '%s'", newToken)
		}

		// 验证响应头中包含新令牌
		if w.Header().Get("X-New-Token") != "refreshed-token" {
			t.Errorf("期望响应头X-New-Token为 'refreshed-token' 但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("使用默认选项", func(t *testing.T) {
		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 从默认选项创建并修改
		opts := DefaultAutoRefreshOptions()
		opts.TokenService = mockService
		opts.RefreshThreshold = 10 * time.Minute // 修改阈值

		// 添加自动刷新中间件
		router.Use(AutoRefresh(opts))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证响应头中包含新令牌
		if w.Header().Get("X-New-Token") != "refreshed-token" {
			t.Errorf("期望响应头X-New-Token为 'refreshed-token' 但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("无令牌类型", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			HeaderName:       "X-API-Token",
			TokenType:        "", // 即使设置为空，在refresh.go中也会被重置为"Bearer"
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Token", "Bearer expiring-token") // 使用Bearer前缀
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调被调用
		if !refreshCalled {
			t.Error("期望调用OnRefresh回调，但未被调用")
		}

		// 验证响应头中包含新令牌
		if w.Header().Get("X-New-Token") != "refreshed-token" {
			t.Errorf("期望响应头X-New-Token为 'refreshed-token' 但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("无授权头", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求（无授权头）
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})

	t.Run("无效的令牌类型前缀", func(t *testing.T) {
		// 跟踪回调是否被调用
		refreshCalled := false

		// 创建一个带有自动刷新中间件的路由器
		router := setupRouter()

		// 添加身份验证中间件来设置令牌上下文
		router.Use(func(c *gin.Context) {
			token := expiringToken
			c.Set(CtxKeyToken, token)
			c.Next()
		})

		// 添加自动刷新中间件
		router.Use(AutoRefresh(AutoRefreshOptions{
			TokenService:     mockService,
			HeaderName:       "Authorization",
			TokenType:        "Bearer",
			RefreshThreshold: 10 * time.Minute,
			OnRefresh: func(c *gin.Context, old, new string) {
				refreshCalled = true
			},
		}))

		// 添加测试路由
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 创建测试请求（使用错误的前缀）
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Wrong expiring-token")
		w := httptest.NewRecorder()

		// 处理请求
		router.ServeHTTP(w, req)

		// 验证响应状态码
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 验证刷新回调未被调用
		if refreshCalled {
			t.Error("期望不调用OnRefresh回调，但被调用了")
		}

		// 验证响应头中不包含新令牌
		if w.Header().Get("X-New-Token") != "" {
			t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
		}
	})
}

func TestAutoRefreshOptions(t *testing.T) {
	// 测试默认选项
	opts := DefaultAutoRefreshOptions()

	if opts.HeaderName != "Authorization" {
		t.Errorf("期望默认HeaderName为 'Authorization'，但得到 '%s'", opts.HeaderName)
	}

	if opts.TokenType != "Bearer" {
		t.Errorf("期望默认TokenType为 'Bearer'，但得到 '%s'", opts.TokenType)
	}

	if opts.RefreshThreshold != 15*time.Minute {
		t.Errorf("期望默认RefreshThreshold为15分钟，但得到 %v", opts.RefreshThreshold)
	}
}

func TestAutoRefreshWithZeroRefreshThreshold(t *testing.T) {
	// 创建即将过期的令牌
	expiringToken := &Token{
		UserID:    "test-user",
		Roles:     []string{"admin"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// 创建模拟令牌服务
	mockService := &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			return expiringToken, nil
		},
		refreshFunc: func(tokenString string) (string, error) {
			return "refreshed-token", nil
		},
		parseFunc: func(tokenString string) (*Token, error) {
			return expiringToken, nil
		},
	}

	// 创建一个带有自动刷新中间件的路由器（零刷新阈值）
	router := setupRouter()

	// 添加身份验证中间件来设置令牌上下文
	router.Use(func(c *gin.Context) {
		c.Set(CtxKeyToken, expiringToken)
		c.Next()
	})

	// 添加自动刷新中间件
	router.Use(AutoRefresh(AutoRefreshOptions{
		TokenService:     mockService,
		RefreshThreshold: 0, // 零刷新阈值，应该使用默认值
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
	}

	// 令牌应该被刷新，因为默认阈值为15分钟
	if w.Header().Get("X-New-Token") == "" {
		t.Error("期望响应头X-New-Token不为空，但为空")
	}
}

func TestAutoRefreshWithContextToken(t *testing.T) {
	// 创建一个类型不是*jwt.Token的令牌
	invalidTypeToken := "not-a-token-object"

	// 创建模拟令牌服务
	mockService := newMockTokenService()

	// 创建一个带有自动刷新中间件的路由器
	router := setupRouter()

	// 添加中间件设置错误类型的令牌
	router.Use(func(c *gin.Context) {
		c.Set(CtxKeyToken, invalidTypeToken)
		c.Next()
	})

	// 添加自动刷新中间件
	router.Use(AutoRefresh(AutoRefreshOptions{
		TokenService: mockService,
	}))

	// 添加测试路由
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// 创建测试请求
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	// 处理请求
	router.ServeHTTP(w, req)

	// 验证响应状态码
	if w.Code != http.StatusOK {
		t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
	}

	// 由于令牌类型错误，不应刷新令牌
	if w.Header().Get("X-New-Token") != "" {
		t.Errorf("期望响应头X-New-Token为空，但得到 '%s'", w.Header().Get("X-New-Token"))
	}
}
