package rbac

import (
	"errors"

	"github.com/simp-lee/guardian/storage"
)

// Role represents a role in the RBAC system.
type Role = storage.Role

// Service defines the interface for role-based access control.
type Service interface {
	// Role management
	CreateRole(id, name, description string) error
	GetRole(roleID string) (*Role, error)
	UpdateRole(roleID, name, description string) error
	DeleteRole(roleID string) error
	ListRoles() ([]*Role, error)

	// User-Role management
	AddUserRole(userID, roleID string) error
	RemoveUserRole(userID, roleID string) error
	GetUserRoles(userID string) ([]string, error)

	// Permission management
	AddRolePermission(roleID, resource, action string) error
	AddRolePermissions(roleID, resource string, actions []string) error
	RemoveRolePermission(roleID, resource string) error
	HasPermission(userID, resource, action string) (bool, error)

	// User-specific permission management
	AddUserPermission(userID, resource, action string) error
	AddUserPermissions(userID, resource string, actions []string) error
	RemoveUserPermission(userID, resource, action string) error
	RemoveAllUserPermissions(userID string) error
	HasUserDirectPermission(userID, resource, action string) (bool, error)
}

// Common errors returned by the RBAC service
var (
	ErrInvalidRoleID           = errors.New("rbac: invalid role ID")
	ErrEmptyUserID             = errors.New("rbac: empty user ID")
	ErrInvalidResource         = errors.New("rbac: invalid resource")
	ErrInvalidAction           = errors.New("rbac: invalid action")
	ErrPermissionAlreadyExists = errors.New("rbac: permission already exists")
)

// New creates a new RBAC service with the provided storage.
func New(storage storage.Storage) Service {
	return newRBACService(storage)
}
