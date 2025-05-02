package storage

import (
	"errors"
	"time"
)

// Role represents a role in the RBAC system.
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions map[string][]string // resource -> []actions
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NewRole creates a new role.
func NewRole(id, name, description string) *Role {
	now := time.Now()
	return &Role{
		ID:          id,
		Name:        name,
		Description: description,
		Permissions: make(map[string][]string),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// Storage defines the interface for persistence operations.
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

	Close() error
}

// Common errors
var (
	ErrRoleNotFound        = errors.New("storage: role not found")
	ErrRoleAlreadyExists   = errors.New("storage: role already exists")
	ErrUserAlreadyHasRole  = errors.New("storage: user already has role")
	ErrUserDoesNotHaveRole = errors.New("storage: user does not have role")
	ErrPermissionNotFound  = errors.New("storage: permission not found")
)
