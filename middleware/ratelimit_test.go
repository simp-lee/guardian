package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimitMiddleware(t *testing.T) {
	t.Run("基本速率限制功能", func(t *testing.T) {
		// 创建一个带有速率限制的路由器（每分钟60个请求，突发为3）
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 60, // 每秒1个请求
			Burst:             3,  // 突发允许3个请求
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送多个请求测试速率限制
		var w *httptest.ResponseRecorder
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234" // 设置固定IP以确保一致的测试结果

		// 前3个请求应该成功（因为突发值为3）
		for i := 0; i < 3; i++ {
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("请求 #%d: 期望状态码 %d 但得到 %d", i+1, http.StatusOK, w.Code)
			}
		}

		// 第4个请求应该失败
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("请求 #4: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 确认响应体包含适当的错误消息
		if !strings.Contains(w.Body.String(), "too many requests") {
			t.Errorf("期望错误消息包含 'too many requests' 但得到: %s", w.Body.String())
		}
	})

	t.Run("不同IP地址的独立速率限制", func(t *testing.T) {
		// 创建一个带有速率限制的路由器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 5, // 低速率，大约每12秒添加一个令牌
			Burst:             2, // 初始允许2个请求
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// IP 1发送请求直到达到限制
		req1, _ := http.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "192.168.1.1:1234"

		// 首先发送2个请求（消耗掉初始令牌桶中的所有令牌）
		for i := 0; i < 2; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req1)
			if w.Code != http.StatusOK {
				t.Errorf("IP1 请求 #%d: 期望状态码 %d 但得到 %d", i+1, http.StatusOK, w.Code)
			}
		}

		// 第三个请求应该触发速率限制
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req1)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("IP1 请求 #3: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// IP 2应该有自己独立的速率限制，可以成功发送请求
		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.2:1234"

		w = httptest.NewRecorder()
		router.ServeHTTP(w, req2)
		if w.Code != http.StatusOK {
			t.Errorf("IP2 请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// IP 2应该可以发送第二个请求
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req2)
		if w.Code != http.StatusOK {
			t.Errorf("IP2 请求 #2: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// IP 2的第三个请求也应该触发限制
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req2)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("IP2 请求 #3: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}
	})

	t.Run("响应头包含速率限制信息", func(t *testing.T) {
		// 创建一个带有速率限制的路由器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 30,
			Burst:             5,
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// 检查响应头
		if w.Header().Get("X-RateLimit-Limit") != "30" {
			t.Errorf("期望X-RateLimit-Limit为30，但得到 %s", w.Header().Get("X-RateLimit-Limit"))
		}

		// 请注意：剩余令牌是个大致值，可能会有所不同，所以我们只检查它存在但不检查具体值
		if w.Header().Get("X-RateLimit-Remaining") == "" {
			t.Error("期望设置X-RateLimit-Remaining头，但未找到")
		}
	})

	t.Run("自定义错误处理器", func(t *testing.T) {
		// 跟踪是否调用了错误处理器
		errorHandlerCalled := false

		// 创建一个带有自定义错误处理器的路由器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 5,
			Burst:             1,
			ErrorHandler: func(c *gin.Context, err error) {
				errorHandlerCalled = true
				c.JSON(http.StatusTooManyRequests, gin.H{"custom_error": "请求过多"})
				c.Abort()
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送请求直到超过限制
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"

		// 第一个请求应该成功
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 第二个请求应该触发自定义错误处理器
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !errorHandlerCalled {
			t.Error("期望调用自定义错误处理器，但未被调用")
		}

		if w.Code != http.StatusTooManyRequests {
			t.Errorf("请求 #2: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		if w.Body.String() != `{"custom_error":"请求过多"}` {
			t.Errorf("期望自定义错误消息，但得到: %s", w.Body.String())
		}
	})

	t.Run("自定义键提取器", func(t *testing.T) {
		// 创建一个使用自定义键提取器的路由器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 5,
			Burst:             1,
			KeyExtractor: func(c *gin.Context) string {
				// 使用用户ID作为速率限制键
				return c.GetHeader("X-User-ID")
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 为相同的IP但不同的用户ID发送请求
		req1, _ := http.NewRequest("GET", "/test", nil)
		req1.RemoteAddr = "192.168.1.1:1234"
		req1.Header.Set("X-User-ID", "user1")

		req2, _ := http.NewRequest("GET", "/test", nil)
		req2.RemoteAddr = "192.168.1.1:1234"  // 相同IP
		req2.Header.Set("X-User-ID", "user2") // 不同用户

		// 用户1的第一个请求应该成功
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req1)
		if w.Code != http.StatusOK {
			t.Errorf("用户1 请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 用户1的第二个请求应该被限制
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req1)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("用户1 请求 #2: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 用户2的请求应该成功（因为使用不同的用户ID作为键）
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req2)
		if w.Code != http.StatusOK {
			t.Errorf("用户2 请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
	})

	t.Run("测试自动过期和清理", func(t *testing.T) {
		// 创建一个带有非常短的过期时间的速率限制器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 5,
			Burst:             1,
			CleanupInterval:   50 * time.Millisecond,  // 非常短的清理间隔
			ExpirationTime:    100 * time.Millisecond, // 非常短的过期时间
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送请求直到超过限制
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"

		// 第一个请求应该成功
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 第二个请求应该被限制
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("请求 #2: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 等待过期
		time.Sleep(150 * time.Millisecond)

		// 现在应该可以再次发送请求
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("过期后请求: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
	})

	t.Run("并发请求", func(t *testing.T) {
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             5,
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送10个并发请求
		var wg sync.WaitGroup
		successCount := 0
		limitedCount := 0
		var mu sync.Mutex

		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.168.1.1:1234"
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				mu.Lock()
				defer mu.Unlock()

				if w.Code == http.StatusOK {
					successCount++
				} else if w.Code == http.StatusTooManyRequests {
					limitedCount++
				}
			}()
		}

		wg.Wait()

		// 验证请求计数
		t.Logf("成功请求: %d, 被限制请求: %d", successCount, limitedCount)

		if successCount+limitedCount != 10 {
			t.Errorf("期望处理10个请求，但实际上处理了 %d 个", successCount+limitedCount)
		}

		// 由于令牌桶初始有5个令牌，允许大约6个请求通过（初始5个+大约1个新生成的）
		if successCount < 5 || successCount > 7 {
			t.Errorf("期望成功请求数量在5-7之间，但得到 %d", successCount)
		}
	})

	t.Run("回调函数测试", func(t *testing.T) {
		// 跟踪回调调用
		rateLimitedCalled := false
		var rateLimitedKey string

		requestCalled := false
		var requestKey string
		var requestRemaining int // Will store remaining requests count from callback

		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 5,
			Burst:             1,
			OnRateLimited: func(key string, c *gin.Context) {
				rateLimitedCalled = true
				rateLimitedKey = key
			},
			OnRequest: func(key string, remaining int, c *gin.Context) {
				requestCalled = true
				requestKey = key
				requestRemaining = remaining
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送请求
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"

		// 第一个请求应该调用OnRequest
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !requestCalled {
			t.Error("期望调用OnRequest回调，但未被调用")
		}

		if requestKey != "192.168.1.1" {
			t.Errorf("期望请求键为 '192.168.1.1'，但得到 '%s'", requestKey)
		}

		// Verify we have a valid remaining count
		if requestRemaining < 0 {
			t.Errorf("期望剩余请求数大于等于0，但得到 %d", requestRemaining)
		}

		// 第二个请求应该触发OnRateLimited
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !rateLimitedCalled {
			t.Error("期望调用OnRateLimited回调，但未被调用")
		}

		if rateLimitedKey != "192.168.1.1" {
			t.Errorf("期望速率限制键为 '192.168.1.1'，但得到 '%s'", rateLimitedKey)
		}
	})

	t.Run("清理函数测试", func(t *testing.T) {
		// 调用清理函数不应该导致panic
		_, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
		})

		// 调用cleanup不应导致错误
		cleanup()

		// 调用多次cleanup也应该安全
		cleanup()
	})

	t.Run("默认选项", func(t *testing.T) {
		opts := DefaultRateLimitOptions()

		if opts.RequestsPerMinute != 60 {
			t.Errorf("期望默认RequestsPerMinute为60，但得到 %d", opts.RequestsPerMinute)
		}

		if opts.Burst != 60 {
			t.Errorf("期望默认Burst为60，但得到 %d", opts.Burst)
		}

		if opts.CleanupInterval != 5*time.Minute {
			t.Errorf("期望默认CleanupInterval为5分钟，但得到 %v", opts.CleanupInterval)
		}

		if opts.ExpirationTime != 10*time.Minute {
			t.Errorf("期望默认ExpirationTime为10分钟，但得到 %v", opts.ExpirationTime)
		}

		if opts.ErrorHandler == nil {
			t.Error("期望默认ErrorHandler不为nil")
		}

		if opts.KeyExtractor == nil {
			t.Error("期望默认KeyExtractor不为nil")
		}

		if opts.OnRateLimited == nil {
			t.Error("期望默认OnRateLimited不为nil")
		}

		if opts.OnRequest == nil {
			t.Error("期望默认OnRequest不为nil")
		}
	})

	t.Run("零值选项", func(t *testing.T) {
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送请求
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// 请求应该成功
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 应该有默认的速率限制头
		if w.Header().Get("X-RateLimit-Limit") != "60" {
			t.Errorf("期望X-RateLimit-Limit为60，但得到 %s", w.Header().Get("X-RateLimit-Limit"))
		}
	})

	t.Run("负值选项", func(t *testing.T) {
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: -10,
			Burst:             -5,
			CleanupInterval:   -1 * time.Minute,
			ExpirationTime:    -5 * time.Minute,
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 发送请求
		req, _ := http.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// 请求应该成功，并使用默认值
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 应该有默认的速率限制头
		if w.Header().Get("X-RateLimit-Limit") != "60" {
			t.Errorf("期望X-RateLimit-Limit为60，但得到 %s", w.Header().Get("X-RateLimit-Limit"))
		}
	})
}

func TestRateLimitMiddleware2(t *testing.T) {
	t.Run("基本速率限制功能", func(t *testing.T) {
		// 跟踪回调是否被调用
		rateLimitedCalled := false
		requestCalled := false
		var remaining int

		// 创建一个带有速率限制的路由器
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             2,
			OnRateLimited: func(key string, c *gin.Context) {
				rateLimitedCalled = true
			},
			OnRequest: func(key string, rem int, c *gin.Context) {
				requestCalled = true
				remaining = rem
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 第一个请求应该成功并且消耗一个令牌
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// 验证回调和响应
		if !requestCalled {
			t.Error("期望调用OnRequest回调，但未被调用")
		}
		if rateLimitedCalled {
			t.Error("不期望调用OnRateLimited回调，但被调用了")
		}
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
		if remaining != 1 { // 突发值为2，使用1个后剩余1个
			t.Errorf("期望剩余令牌为1，但得到 %d", remaining)
		}

		// 检查响应头
		if w.Header().Get("X-RateLimit-Remaining") != "1" {
			t.Errorf("期望X-RateLimit-Remaining为'1'，但得到'%s'", w.Header().Get("X-RateLimit-Remaining"))
		}
		if w.Header().Get("X-RateLimit-Limit") != "10" {
			t.Errorf("期望X-RateLimit-Limit为'10'，但得到'%s'", w.Header().Get("X-RateLimit-Limit"))
		}

		// 第二个请求应该成功，但没有剩余令牌
		requestCalled = false
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !requestCalled {
			t.Error("期望调用OnRequest回调，但未被调用")
		}
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
		if remaining != 0 { // 使用2个后剩余0个
			t.Errorf("期望剩余令牌为0，但得到 %d", remaining)
		}

		// 第三个请求应该失败（超过突发限制）
		requestCalled = false
		rateLimitedCalled = false
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if requestCalled {
			t.Error("不期望调用OnRequest回调，但被调用了")
		}
		if !rateLimitedCalled {
			t.Error("期望调用OnRateLimited回调，但未被调用")
		}
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}
	})

	t.Run("令牌恢复", func(t *testing.T) {
		// 使用高速率以便快速测试
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 60, // 每秒1个令牌
			Burst:             1,
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"

		// 第一个请求应该成功
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 第二个请求应该失败（因为没有足够的令牌）
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 等待足够的时间以便生成新令牌
		time.Sleep(1100 * time.Millisecond) // 稍微多于1秒，确保有新令牌

		// 现在应该有一个令牌，请求应该成功
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
	})

	t.Run("不同IP不共享限制", func(t *testing.T) {
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             1,
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// IP 1的第一个请求应该成功
		reqIP1, _ := http.NewRequest("GET", "/test", nil)
		reqIP1.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, reqIP1)
		if w.Code != http.StatusOK {
			t.Errorf("IP 1请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// IP 1的第二个请求应该失败
		w = httptest.NewRecorder()
		router.ServeHTTP(w, reqIP1)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("IP 1请求 #2: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// IP 2的请求应该成功（不同IP不共享限制）
		reqIP2, _ := http.NewRequest("GET", "/test", nil)
		reqIP2.RemoteAddr = "192.168.1.2:1234"
		w = httptest.NewRecorder()
		router.ServeHTTP(w, reqIP2)
		if w.Code != http.StatusOK {
			t.Errorf("IP 2请求: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
	})

	t.Run("自定义键提取器", func(t *testing.T) {
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             1,
			// 使用用户ID作为键（从请求头中获取）
			KeyExtractor: func(c *gin.Context) string {
				return c.GetHeader("X-User-ID")
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 用户1的第一个请求应该成功
		reqUser1, _ := http.NewRequest("GET", "/test", nil)
		reqUser1.Header.Set("X-User-ID", "user1")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, reqUser1)
		if w.Code != http.StatusOK {
			t.Errorf("用户1请求 #1: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 用户1的第二个请求应该失败
		w = httptest.NewRecorder()
		router.ServeHTTP(w, reqUser1)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("用户1请求 #2: 期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 用户2的请求应该成功（不同用户不共享限制）
		reqUser2, _ := http.NewRequest("GET", "/test", nil)
		reqUser2.Header.Set("X-User-ID", "user2")
		w = httptest.NewRecorder()
		router.ServeHTTP(w, reqUser2)
		if w.Code != http.StatusOK {
			t.Errorf("用户2请求: 期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}
	})

	t.Run("自定义错误处理器", func(t *testing.T) {
		customErrorCalled := false

		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             1,
			ErrorHandler: func(c *gin.Context, err error) {
				customErrorCalled = true
				c.JSON(http.StatusTooManyRequests, gin.H{
					"custom_error": "rate limit exceeded",
				})
				c.Abort()
			},
		})
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 第一个请求应该成功
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 第二个请求应该失败并使用自定义错误处理器
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		if !customErrorCalled {
			t.Error("期望调用自定义错误处理器，但未被调用")
		}
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}
		if !strings.Contains(w.Body.String(), "custom_error") {
			t.Errorf("期望响应包含'custom_error'，但得到: %s", w.Body.String())
		}
	})

	t.Run("默认选项", func(t *testing.T) {
		// 使用默认选项
		opts := DefaultRateLimitOptions()
		// 将突发值设置为1以便测试
		opts.Burst = 1

		router := setupRouter()
		middleware, cleanup := RateLimit(opts)
		defer cleanup()

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 第一个请求应该成功
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 检查默认响应头
		if w.Header().Get("X-RateLimit-Limit") != "60" {
			t.Errorf("期望X-RateLimit-Limit为'60'，但得到'%s'", w.Header().Get("X-RateLimit-Limit"))
		}

		// 第二个请求应该失败
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}
	})

	t.Run("清理功能", func(t *testing.T) {
		// 使用非常短的过期时间测试清理功能
		router := setupRouter()
		middleware, cleanup := RateLimit(RateLimitOptions{
			RequestsPerMinute: 10,
			Burst:             1,
			CleanupInterval:   50 * time.Millisecond,
			ExpirationTime:    100 * time.Millisecond,
		})

		router.Use(middleware)
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		// 第一个请求应该成功
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 第二个请求应该失败（速率限制）
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusTooManyRequests {
			t.Errorf("期望状态码 %d 但得到 %d", http.StatusTooManyRequests, w.Code)
		}

		// 等待条目过期并被清理
		time.Sleep(200 * time.Millisecond)

		// 现在应该能够再次请求
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("清理后，期望状态码 %d 但得到 %d", http.StatusOK, w.Code)
		}

		// 测试清理函数
		cleanup()
		// 确保清理函数可以多次调用而不会panic
		cleanup()
	})
}
