package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/simp-lee/guardian/jwt"
	"github.com/simp-lee/guardian/rbac"
)

func init() {
	// 将Gin设置为测试模式以减少测试日志输出
	gin.SetMode(gin.TestMode)
}

// Token 是jwt.Token的别名，用于测试
type Token = jwt.Token

// Role 是rbac.Role的别名，用于测试
//type Role = rbac.Role

// 错误类型的别名
var (
	ErrInvalidToken = jwt.ErrInvalidToken
	ErrExpiredToken = jwt.ErrExpiredToken
	ErrRevokedToken = jwt.ErrRevokedToken
	ErrRoleNotFound = rbac.ErrInvalidRoleID
	ErrUserNotFound = rbac.ErrEmptyUserID
)

// mockTokenService 实现用于测试的TokenService接口
type mockTokenService struct {
	validateFunc      func(tokenString string) (*Token, error)
	generateFunc      func(userID string, roles []string, expiresIn time.Duration) (string, error)
	refreshFunc       func(tokenString string) (string, error)
	revokeFunc        func(tokenString string) error
	revokeAllUserFunc func(userID string) error
	parseFunc         func(tokenString string) (*Token, error)
	isRevokedFunc     func(tokenID string) bool
}

func (m *mockTokenService) ValidateToken(tokenString string) (*Token, error) {
	return m.validateFunc(tokenString)
}

func (m *mockTokenService) GenerateToken(userID string, roles []string, expiresIn time.Duration) (string, error) {
	return m.generateFunc(userID, roles, expiresIn)
}

func (m *mockTokenService) RefreshToken(tokenString string) (string, error) {
	return m.refreshFunc(tokenString)
}

func (m *mockTokenService) RevokeToken(tokenString string) error {
	return m.revokeFunc(tokenString)
}

func (m *mockTokenService) RevokeAllUserTokens(userID string) error {
	return m.revokeAllUserFunc(userID)
}

func (m *mockTokenService) ParseToken(tokenString string) (*Token, error) {
	return m.parseFunc(tokenString)
}

func (m *mockTokenService) IsTokenRevoked(tokenID string) bool {
	return m.isRevokedFunc(tokenID)
}

func (m *mockTokenService) Close() {}

// mockRBACService 实现用于测试的RBACService接口
type mockRBACService struct {
	hasPermissionFunc func(userID string, resource string, action string) (bool, error)
	getUserRolesFunc  func(userID string) ([]string, error)
}

func (m *mockRBACService) HasPermission(userID string, resource string, action string) (bool, error) {
	return m.hasPermissionFunc(userID, resource, action)
}

func (m *mockRBACService) GetUserRoles(userID string) ([]string, error) {
	return m.getUserRolesFunc(userID)
}

// 实现其余RBAC接口方法，仅供测试
func (m *mockRBACService) CreateRole(id, name, description string) error {
	return nil
}

func (m *mockRBACService) GetRole(roleID string) (*rbac.Role, error) {
	return nil, nil
}

func (m *mockRBACService) UpdateRole(roleID, name, description string) error {
	return nil
}

func (m *mockRBACService) DeleteRole(roleID string) error {
	return nil
}

func (m *mockRBACService) ListRoles() ([]*rbac.Role, error) {
	return nil, nil
}

func (m *mockRBACService) AddUserRole(userID, roleID string) error {
	return nil
}

func (m *mockRBACService) RemoveUserRole(userID, roleID string) error {
	return nil
}

func (m *mockRBACService) AddRolePermission(roleID, resource, action string) error {
	return nil
}

func (m *mockRBACService) AddRolePermissions(roleID, resource string, actions []string) error {
	return nil
}

func (m *mockRBACService) RemoveRolePermission(roleID, resource string) error {
	return nil
}

// setupRouter 创建一个用于测试的新Gin路由器
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

// 创建标准的模拟令牌服务，简化测试设置
func newMockTokenService() *mockTokenService {
	return &mockTokenService{
		validateFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
		generateFunc: func(userID string, roles []string, expiresIn time.Duration) (string, error) {
			return "new-token", nil
		},
		refreshFunc: func(tokenString string) (string, error) {
			return "refreshed-token", nil
		},
		revokeFunc: func(tokenString string) error {
			return nil
		},
		revokeAllUserFunc: func(userID string) error {
			return nil
		},
		parseFunc: func(tokenString string) (*Token, error) {
			if tokenString == "valid-token" {
				return &Token{
					UserID: "test-user",
					Roles:  []string{"admin"},
				}, nil
			}
			return nil, ErrInvalidToken
		},
		isRevokedFunc: func(tokenID string) bool {
			return false
		},
	}
}
