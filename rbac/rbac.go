package rbac

import (
	"strings"
	"time"

	"github.com/simp-lee/guardian/storage"
)

type rbacService struct {
	storage storage.Storage
}

func newRBACService(storage storage.Storage) Service {
	return &rbacService{
		storage: storage,
	}
}

func (s *rbacService) CreateRole(id, name, description string) error {
	if id == "" {
		return ErrInvalidRoleID
	}

	role := storage.NewRole(id, name, description)
	return s.storage.CreateRole(role)
}

func (s *rbacService) GetRole(roleID string) (*Role, error) {
	if roleID == "" {
		return nil, ErrInvalidRoleID
	}

	return s.storage.GetRole(roleID)
}

func (s *rbacService) UpdateRole(roleID, name, description string) error {
	if roleID == "" {
		return ErrInvalidRoleID
	}

	role, err := s.storage.GetRole(roleID)
	if err != nil {
		return err
	}

	role.Name = name
	role.Description = description
	role.UpdatedAt = time.Now()

	return s.storage.UpdateRole(role)
}

func (s *rbacService) DeleteRole(roleID string) error {
	if roleID == "" {
		return ErrInvalidRoleID
	}

	return s.storage.DeleteRole(roleID)
}

func (s *rbacService) ListRoles() ([]*Role, error) {
	return s.storage.ListRoles()
}

func (s *rbacService) AddUserRole(userID, roleID string) error {
	if userID == "" {
		return ErrEmptyUserID
	}

	if roleID == "" {
		return ErrInvalidRoleID
	}

	return s.storage.AddUserRole(userID, roleID)
}

func (s *rbacService) RemoveUserRole(userID, roleID string) error {
	if userID == "" {
		return ErrEmptyUserID
	}

	if roleID == "" {
		return ErrInvalidRoleID
	}

	return s.storage.RemoveUserRole(userID, roleID)
}

func (s *rbacService) GetUserRoles(userID string) ([]string, error) {
	if userID == "" {
		return nil, ErrEmptyUserID
	}

	return s.storage.GetUserRoles(userID)
}

func (s *rbacService) AddRolePermission(roleID, resource, action string) error {
	if roleID == "" {
		return ErrInvalidRoleID
	}

	if resource == "" {
		return ErrInvalidResource
	}

	if action == "" {
		return ErrInvalidAction
	}

	// Check if permission already exists
	role, err := s.storage.GetRole(roleID)
	if err != nil {
		return err
	}

	if role.Permissions != nil {
		if actions, exists := role.Permissions[resource]; exists {
			for _, existingAction := range actions {
				if existingAction == action {
					return ErrPermissionAlreadyExists
				}
			}
		}
	}

	return s.storage.AddRolePermission(roleID, resource, action)
}

func (s *rbacService) AddRolePermissions(roleID, resource string, actions []string) error {
	if roleID == "" {
		return ErrInvalidRoleID
	}

	if resource == "" {
		return ErrInvalidResource
	}

	for _, action := range actions {
		if action == "" {
			return ErrInvalidAction
		}

		err := s.AddRolePermission(roleID, resource, action)
		if err != nil && err != ErrPermissionAlreadyExists {
			return err
		}
	}

	return nil
}

func (s *rbacService) RemoveRolePermission(roleID, resource string) error {
	if roleID == "" {
		return ErrInvalidRoleID
	}

	if resource == "" {
		return ErrInvalidResource
	}

	return s.storage.RemoveRolePermission(roleID, resource)
}

// HasPermission checks if a user has permission to perform an action on a resource.
// It evaluates permissions based on all roles assigned to the user and supports
// hierarchical resources and wildcard patterns.
//
// Permission Evaluation Rules:
// 1. Direct Permission: Checks if any of the user's roles has an exact permission match.
// 2. Wildcard Patterns: Supports wildcards for resources and actions:
//
//   - "*" as a resource matches any resource
//
//   - "*" as an action matches any action on the specified resource
//
//   - "*/*" grants all permissions on all resources
//
//     3. Hierarchical Resources: Resources can be structured hierarchically using "/" delimiter.
//     IMPORTANT: Hierarchical inheritance works ONLY through explicit wildcard patterns:
//
//   - For a resource path like "articles/drafts/special":
//     a) It checks for exact permission match on "articles/drafts/special"
//     b) Then checks for wildcard permissions: "articles/drafts/*" and "articles/*"
//
//   - A permission on "articles/drafts" (without wildcard) does NOT automatically apply to
//     "articles/drafts/special". You must explicitly add "articles/drafts/*" permission.
//
// This design ensures that permissions aren't unintentionally inherited by child resources
// unless explicitly configured using wildcard patterns, providing more precise access control.
//
// Parameters:
//   - userID: The ID of the user to check permissions for
//   - resource: The resource path (can be hierarchical like "articles/drafts/special")
//   - action: The action to perform on the resource (e.g., "read", "write", "delete")
//
// Returns:
//   - bool: True if the user has permission, false otherwise
//   - error: Any error encountered during permission checking
func (s *rbacService) HasPermission(userID string, resource string, action string) (bool, error) {
	if userID == "" {
		return false, ErrEmptyUserID
	}

	if resource == "" {
		return false, ErrInvalidResource
	}

	if action == "" {
		return false, ErrInvalidAction
	}

	roleIDs, err := s.storage.GetUserRoles(userID)
	if err != nil {
		return false, err
	}

	// If the user has no roles, then the user has no permission
	if len(roleIDs) == 0 {
		return false, nil
	}

	for _, roleID := range roleIDs {
		// Check specific permission
		hasPermission, err := s.storage.HasPermission(roleID, resource, action)
		if err == nil && hasPermission {
			return true, nil
		}

		// Check resource wildcard permission
		hasAllResourcesPermission, err := s.storage.HasPermission(roleID, "*", action)
		if err == nil && hasAllResourcesPermission {
			return true, nil
		}

		// Check action wildcard permission
		hasAllActionsPermission, err := s.storage.HasPermission(roleID, resource, "*")
		if err == nil && hasAllActionsPermission {
			return true, nil
		}

		// Check both resource and action wildcard permission
		hasAllPermission, err := s.storage.HasPermission(roleID, "*", "*")
		if err == nil && hasAllPermission {
			return true, nil
		}

		// Check resource hierarchy through explicit wildcard patterns
		// Note: This does NOT check non-wildcard parent resources
		if strings.Contains(resource, "/") {
			resourceParts := strings.Split(resource, "/")
			for i := len(resourceParts) - 1; i > 0; i-- {
				// Generate parent resource with wildcard,
				// e.g., "articles/drafts/special" -> "articles/drafts/*"
				parentResource := strings.Join(resourceParts[:i], "/") + "/*"

				// Check for specific action on parent wildcard resource
				hasHierarchy, err := s.storage.HasPermission(roleID, parentResource, action)
				if err == nil && hasHierarchy {
					return true, nil
				}

				// Check for wildcard action on parent resource
				hasHierarchyWildcard, err := s.storage.HasPermission(roleID, parentResource, "*")
				if err == nil && hasHierarchyWildcard {
					return true, nil
				}
			}
		}
	}

	return false, nil
}
