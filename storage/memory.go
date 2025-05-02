package storage

import (
	"slices"
	"sync"
	"time"
)

// MemoryStorage implements Storage interface using in-memory maps
type MemoryStorage struct {
	mu        sync.RWMutex
	roles     map[string]*Role
	userRoles map[string]map[string]bool // userID -> map[roleID]true
}

// NewMemoryStorage creates a new memory-based storage
func NewMemoryStorage() Storage {
	return &MemoryStorage{
		roles:     make(map[string]*Role),
		userRoles: make(map[string]map[string]bool),
	}
}

func (s *MemoryStorage) CreateRole(role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.ID]; exists {
		return ErrRoleAlreadyExists
	}

	s.roles[role.ID] = role
	return nil
}

func (s *MemoryStorage) GetRole(roleID string) (*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return nil, ErrRoleNotFound
	}
	return role, nil
}

func (s *MemoryStorage) UpdateRole(role *Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.ID]; !exists {
		return ErrRoleNotFound
	}

	role.UpdatedAt = time.Now()
	s.roles[role.ID] = role
	return nil
}

func (s *MemoryStorage) DeleteRole(roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[roleID]; !exists {
		return ErrRoleNotFound
	}

	delete(s.roles, roleID)

	// Remove role from all users
	for userID, roles := range s.userRoles {
		if roles[roleID] {
			delete(s.userRoles[userID], roleID)
		}
	}

	return nil
}

func (s *MemoryStorage) ListRoles() ([]*Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles := make([]*Role, 0, len(s.roles))
	for _, role := range s.roles {
		roles = append(roles, role)
	}

	return roles, nil
}

func (s *MemoryStorage) AddUserRole(userID, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if role exists
	if _, exists := s.roles[roleID]; !exists {
		return ErrRoleNotFound
	}

	// Check if user already has the role
	if _, exists := s.userRoles[userID]; !exists {
		s.userRoles[userID] = make(map[string]bool)
	}

	if s.userRoles[userID][roleID] {
		return ErrUserAlreadyHasRole
	}

	s.userRoles[userID][roleID] = true
	return nil
}

func (s *MemoryStorage) RemoveUserRole(userID, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	userRoles, exists := s.userRoles[userID]
	if !exists || !userRoles[roleID] {
		return ErrUserDoesNotHaveRole
	}

	delete(s.userRoles[userID], roleID)
	return nil
}

func (s *MemoryStorage) GetUserRoles(userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userRoles, exists := s.userRoles[userID]
	if !exists {
		return []string{}, nil
	}

	roleIDs := make([]string, 0, len(userRoles))
	for roleID := range userRoles {
		roleIDs = append(roleIDs, roleID)
	}

	return roleIDs, nil
}

func (s *MemoryStorage) AddRolePermission(roleID, resource, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	role, exists := s.roles[roleID]
	if !exists {
		return ErrRoleNotFound
	}

	if role.Permissions == nil {
		role.Permissions = make(map[string][]string)
	}

	// Check if the resource already exists
	if slices.Contains(role.Permissions[resource], action) {
		return nil // Permission already exists
	}

	// Add permission
	role.Permissions[resource] = append(role.Permissions[resource], action)
	role.UpdatedAt = time.Now()
	return nil
}

func (s *MemoryStorage) RemoveRolePermission(roleID, resource string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	role, exists := s.roles[roleID]
	if !exists {
		return ErrRoleNotFound
	}

	if _, exists := role.Permissions[resource]; !exists {
		return ErrPermissionNotFound
	}

	delete(role.Permissions, resource)
	role.UpdatedAt = time.Now()
	return nil
}

func (s *MemoryStorage) HasPermission(roleID, resource, action string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return false, ErrRoleNotFound
	}

	actions, exists := role.Permissions[resource]
	if !exists {
		return false, nil
	}

	if slices.Contains(actions, action) {
		return true, nil
	}

	return false, nil
}

func (s *MemoryStorage) Close() error {
	// No resources to clean up in memory storage
	return nil
}
