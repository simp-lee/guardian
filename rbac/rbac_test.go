package rbac

import (
	"testing"

	"github.com/simp-lee/guardian/storage"
)

func NewMemoryStorage() storage.Storage {
	return storage.NewMemoryStorage()
}

func NewRBACService(storage storage.Storage) Service {
	return newRBACService(storage)
}

func TestRBACServiceRoleManagement(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role
	err := rbac.CreateRole("admin", "Administrator", "System administrator")
	if err != nil {
		t.Fatalf("Expected successful role creation, but got error: %v", err)
	}

	// Create duplicate role
	err = rbac.CreateRole("admin", "Admin", "")
	if err != storage.ErrRoleAlreadyExists {
		t.Fatalf("Expected creating duplicate role to return ErrRoleAlreadyExists, but got: %v", err)
	}

	// Get role
	role, err := rbac.GetRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role retrieval, but got error: %v", err)
	}
	if role.ID != "admin" || role.Name != "Administrator" {
		t.Fatalf("Expected retrieved role to match created one, but got: %+v", role)
	}

	// Get non-existent role
	_, err = rbac.GetRole("nonexistent")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected getting non-existent role to return ErrRoleNotFound, but got: %v", err)
	}

	// Update role
	err = rbac.UpdateRole("admin", "Super Admin", "Super administrator")
	if err != nil {
		t.Fatalf("Expected successful role update, but got error: %v", err)
	}

	// Verify update
	updatedRole, _ := rbac.GetRole("admin")
	if updatedRole.Name != "Super Admin" || updatedRole.Description != "Super administrator" {
		t.Fatalf("Expected role to be updated, but got: %+v", updatedRole)
	}

	// Update non-existent role
	err = rbac.UpdateRole("nonexistent", "Nonexistent", "")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected updating non-existent role to return ErrRoleNotFound, but got: %v", err)
	}

	// List roles
	roles, err := rbac.ListRoles()
	if err != nil {
		t.Fatalf("Expected successful role listing, but got error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("Expected role count to be 1, but got: %d", len(roles))
	}

	// Delete role
	err = rbac.DeleteRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role deletion, but got error: %v", err)
	}

	// Verify deletion
	roles, _ = rbac.ListRoles()
	if len(roles) != 0 {
		t.Fatalf("Expected role count after deletion to be 0, but got: %d", len(roles))
	}

	// Delete non-existent role
	err = rbac.DeleteRole("nonexistent")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected deleting non-existent role to return ErrRoleNotFound, but got: %v", err)
	}
}

func TestRBACServiceUserRoleManagement(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create roles
	rbac.CreateRole("admin", "Administrator", "")
	rbac.CreateRole("user", "User", "")

	// Add user role
	err := rbac.AddUserRole("user1", "admin")
	if err != nil {
		t.Fatalf("Expected successful user role assignment, but got error: %v", err)
	}

	// Add non-existent role
	err = rbac.AddUserRole("user1", "nonexistent")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected adding non-existent role to return ErrRoleNotFound, but got: %v", err)
	}

	// Add duplicate user role
	err = rbac.AddUserRole("user1", "admin")
	if err != storage.ErrUserAlreadyHasRole {
		t.Fatalf("Expected adding duplicate role to return ErrUserAlreadyHasRole, but got: %v", err)
	}

	// Get user roles
	roles, err := rbac.GetUserRoles("user1")
	if err != nil {
		t.Fatalf("Expected successful user role retrieval, but got error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("Expected user roles to be ['admin'], but got: %v", roles)
	}

	// Get roles for user with no roles
	roles, err = rbac.GetUserRoles("user2")
	if err != nil {
		t.Fatalf("Expected successful empty user role retrieval, but got error: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("Expected user with no roles to have empty role list, but got: %v", roles)
	}

	// Remove user role
	err = rbac.RemoveUserRole("user1", "admin")
	if err != nil {
		t.Fatalf("Expected successful user role removal, but got error: %v", err)
	}

	// Verify removal
	roles, _ = rbac.GetUserRoles("user1")
	if len(roles) != 0 {
		t.Fatalf("Expected user role count after removal to be 0, but got: %d", len(roles))
	}

	// Remove non-existent user role
	err = rbac.RemoveUserRole("user1", "admin")
	if err != storage.ErrUserDoesNotHaveRole {
		t.Fatalf("Expected removing non-existent user role to return ErrUserDoesNotHaveRole, but got: %v", err)
	}
}

func TestRBACServicePermissionManagement(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role
	rbac.CreateRole("admin", "Administrator", "")

	// Add permission
	err := rbac.AddRolePermission("admin", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission addition, but got error: %v", err)
	}

	// Add permission to non-existent role
	err = rbac.AddRolePermission("nonexistent", "users", "read")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected adding permission to non-existent role to return ErrRoleNotFound, but got: %v", err)
	}

	// Add duplicate permission
	err = rbac.AddRolePermission("admin", "users", "read")
	if err != ErrPermissionAlreadyExists {
		t.Fatalf("Expected adding duplicate permission to return ErrPermissionAlreadyExists, but got: %v", err)
	}

	// Add multiple permissions at once
	err = rbac.AddRolePermissions("admin", "posts", []string{"read", "write", "delete"})
	if err != nil {
		t.Fatalf("Expected successful multiple permissions addition, but got error: %v", err)
	}

	// Add multiple permissions to non-existent role
	err = rbac.AddRolePermissions("nonexistent", "posts", []string{"read"})
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected adding multiple permissions to non-existent role to return ErrRoleNotFound, but got: %v", err)
	}

	// Check permission - has permission
	has, err := rbac.HasPermission("mock-user", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission check, but got error: %v", err)
	}
	if has {
		t.Fatal("Expected user without roles to have no permissions, but returned true")
	}

	// Add role to user first
	rbac.AddUserRole("mock-user", "admin")

	// Now check permission again
	has, err = rbac.HasPermission("mock-user", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission check, but got error: %v", err)
	}
	if !has {
		t.Fatal("Expected role to have permission, but returned false")
	}

	// Check permission - doesn't have permission
	has, err = rbac.HasPermission("mock-user", "users", "write")
	if err != nil {
		t.Fatalf("Expected successful permission check, but got error: %v", err)
	}
	if has {
		t.Fatal("Expected role to not have this permission, but returned true")
	}

	// Remove permission
	err = rbac.RemoveRolePermission("admin", "users")
	if err != nil {
		t.Fatalf("Expected successful permission removal, but got error: %v", err)
	}

	// Verify removal
	has, _ = rbac.HasPermission("mock-user", "users", "read")
	if has {
		t.Fatal("Expected permission to be removed, but returned true")
	}

	// Remove permission for non-existent resource
	err = rbac.RemoveRolePermission("admin", "nonexistent")
	if err != storage.ErrPermissionNotFound {
		t.Fatalf("Expected removing non-existent permission to return ErrPermissionNotFound, but got: %v", err)
	}

	// Remove permission from non-existent role
	err = rbac.RemoveRolePermission("nonexistent", "users")
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected removing permission from non-existent role to return ErrRoleNotFound, but got: %v", err)
	}
}

func TestRBACServiceWildcardPermissions(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create roles
	rbac.CreateRole("admin", "Administrator", "")
	rbac.AddUserRole("user1", "admin")

	// Test resource wildcard
	rbac.AddRolePermission("admin", "*", "read")
	has, err := rbac.HasPermission("user1", "any-resource", "read")
	if err != nil || !has {
		t.Fatalf("Expected wildcard resource permission to grant access, err: %v, has: %v", err, has)
	}

	// Test action wildcard
	rbac.AddRolePermission("admin", "posts", "*")
	has, err = rbac.HasPermission("user1", "posts", "any-action")
	if err != nil || !has {
		t.Fatalf("Expected wildcard action permission to grant access, err: %v, has: %v", err, has)
	}

	// Test both wildcards
	rbac.AddRolePermission("admin", "*", "*")
	has, err = rbac.HasPermission("user1", "any-resource", "any-action")
	if err != nil || !has {
		t.Fatalf("Expected full wildcard permission to grant access, err: %v, has: %v", err, has)
	}
}

func TestRBACServiceHierarchicalPermissions(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role
	rbac.CreateRole("editor", "Content Editor", "")
	rbac.AddUserRole("editor1", "editor")

	// Add hierarchical permissions
	rbac.AddRolePermission("editor", "content/*", "read")
	rbac.AddRolePermission("editor", "content/articles/*", "write")

	// Test parent permission inheritance
	has, err := rbac.HasPermission("editor1", "content/images", "read")
	if err != nil || !has {
		t.Fatalf("Expected hierarchical permission to grant access, err: %v, has: %v", err, has)
	}

	// Test more specific permission inheritance
	has, err = rbac.HasPermission("editor1", "content/articles/draft", "write")
	if err != nil || !has {
		t.Fatalf("Expected specific hierarchical permission to grant access, err: %v, has: %v", err, has)
	}

	// Test permission that shouldn't be granted
	has, err = rbac.HasPermission("editor1", "content/images", "delete")
	if err != nil || has {
		t.Fatalf("Expected hierarchical permission not to grant access to other actions, err: %v, has: %v", err, has)
	}

	// Test deeply nested hierarchy
	rbac.AddRolePermission("editor", "a/b/c/*", "read")
	has, err = rbac.HasPermission("editor1", "a/b/c/d/e/f", "read")
	if err != nil || !has {
		t.Fatalf("Expected deeply nested hierarchical permission to grant access, err: %v, has: %v", err, has)
	}
}

func TestRBACServiceEmptyValues(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Test empty role ID
	err := rbac.CreateRole("", "Empty", "")
	if err != ErrInvalidRoleID {
		t.Fatalf("Expected creating role with empty ID to return ErrInvalidRoleID, but got: %v", err)
	}

	// Create valid role for testing
	rbac.CreateRole("test-role", "Test", "")

	// Test empty user ID
	err = rbac.AddUserRole("", "test-role")
	if err != ErrEmptyUserID {
		t.Fatalf("Expected adding role to empty user ID to return ErrEmptyUserID, but got: %v", err)
	}

	// Test empty resource
	err = rbac.AddRolePermission("test-role", "", "read")
	if err != ErrInvalidResource {
		t.Fatalf("Expected adding permission with empty resource to return ErrInvalidResource, but got: %v", err)
	}

	// Test empty action
	err = rbac.AddRolePermission("test-role", "resource", "")
	if err != ErrInvalidAction {
		t.Fatalf("Expected adding permission with empty action to return ErrInvalidAction, but got: %v", err)
	}

	// Test empty user ID for GetUserRoles
	_, err = rbac.GetUserRoles("")
	if err != ErrEmptyUserID {
		t.Fatalf("Expected getting roles for empty user ID to return ErrEmptyUserID, but got: %v", err)
	}

	// Test empty user ID for HasPermission
	_, err = rbac.HasPermission("", "resource", "action")
	if err != ErrEmptyUserID {
		t.Fatalf("Expected checking permission with empty user ID to return ErrEmptyUserID, but got: %v", err)
	}

	// Test empty resource for HasPermission
	_, err = rbac.HasPermission("user", "", "action")
	if err != ErrInvalidResource {
		t.Fatalf("Expected checking permission with empty resource to return ErrInvalidResource, but got: %v", err)
	}

	// Test empty action for HasPermission
	_, err = rbac.HasPermission("user", "resource", "")
	if err != ErrInvalidAction {
		t.Fatalf("Expected checking permission with empty action to return ErrInvalidAction, but got: %v", err)
	}
}

func TestRBACUserWithMultipleRoles(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create roles with different permissions
	rbac.CreateRole("role1", "Role 1", "")
	rbac.CreateRole("role2", "Role 2", "")

	rbac.AddRolePermission("role1", "resource1", "read")
	rbac.AddRolePermission("role2", "resource2", "write")

	// Assign both roles to user
	rbac.AddUserRole("multi-role-user", "role1")
	rbac.AddUserRole("multi-role-user", "role2")

	// Check permissions from both roles
	has1, err1 := rbac.HasPermission("multi-role-user", "resource1", "read")
	has2, err2 := rbac.HasPermission("multi-role-user", "resource2", "write")

	if err1 != nil || !has1 {
		t.Fatalf("User should have permission from role1, err: %v, has: %v", err1, has1)
	}

	if err2 != nil || !has2 {
		t.Fatalf("User should have permission from role2, err: %v, has: %v", err2, has2)
	}
}

func TestRBACDeletingRoleRemovesUserAssignments(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role and assign to user
	rbac.CreateRole("temp-role", "Temporary", "")
	rbac.AddUserRole("test-user", "temp-role")

	// Verify role assignment
	roles, _ := rbac.GetUserRoles("test-user")
	if len(roles) != 1 || roles[0] != "temp-role" {
		t.Fatalf("Expected user to have role 'temp-role', but got: %v", roles)
	}

	// Delete the role
	rbac.DeleteRole("temp-role")

	// Check that user no longer has the deleted role
	roles, _ = rbac.GetUserRoles("test-user")
	if len(roles) != 0 {
		t.Fatalf("Expected user to have no roles after role deletion, but got: %v", roles)
	}
}

func TestRBACEmptyActionsList(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role
	rbac.CreateRole("test-role", "Test Role", "")

	// Test adding empty actions list
	err := rbac.AddRolePermissions("test-role", "resource", []string{})
	if err != nil {
		t.Fatalf("Expected adding empty actions list to succeed, but got error: %v", err)
	}

	// Verify no actions were added
	rbac.AddUserRole("test-user", "test-role")
	has, err := rbac.HasPermission("test-user", "resource", "read")
	if err != nil || has {
		t.Fatalf("Expected no permissions after adding empty actions list, err: %v, has: %v", err, has)
	}
}

func TestRBACConcurrentPermissions(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create roles with overlapping permissions
	rbac.CreateRole("role1", "Role 1", "")
	rbac.CreateRole("role2", "Role 2", "")

	// Add same permission to both roles
	rbac.AddRolePermission("role1", "shared", "read")
	rbac.AddRolePermission("role2", "shared", "read")

	// Assign both roles to user
	rbac.AddUserRole("concurrent-user", "role1")
	rbac.AddUserRole("concurrent-user", "role2")

	// Remove permission from one role
	rbac.RemoveRolePermission("role1", "shared")

	// User should still have permission through role2
	has, err := rbac.HasPermission("concurrent-user", "shared", "read")
	if err != nil || !has {
		t.Fatalf("Expected user to still have permission through role2, err: %v, has: %v", err, has)
	}
}

func TestRBACRolePermissionRemovalEdgeCases(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role
	rbac.CreateRole("test-role", "Test Role", "")

	// Remove non-existent permission from valid role
	err := rbac.RemoveRolePermission("test-role", "nonexistent-resource")
	if err != storage.ErrPermissionNotFound {
		t.Fatalf("Expected removing non-existent permission to return ErrPermissionNotFound, but got: %v", err)
	}

	// Add permission then remove it
	rbac.AddRolePermission("test-role", "resource", "read")
	err = rbac.RemoveRolePermission("test-role", "resource")
	if err != nil {
		t.Fatalf("Expected successful permission removal, but got error: %v", err)
	}

	// Remove the same permission again (already removed)
	err = rbac.RemoveRolePermission("test-role", "resource")
	if err != storage.ErrPermissionNotFound {
		t.Fatalf("Expected removing already removed permission to return ErrPermissionNotFound, but got: %v", err)
	}
}

func TestRBACAddRolePermissionsErrorHandling(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Test with empty role ID (input validation errors should happen before role existence check)
	err := rbac.AddRolePermissions("", "resource", []string{"read"})
	if err != ErrInvalidRoleID {
		t.Fatalf("Expected adding permissions with empty role ID to return ErrInvalidRoleID, but got: %v", err)
	}

	// Test with empty resource (input validation errors should happen before role existence check)
	err = rbac.AddRolePermissions("role-id", "", []string{"read"})
	if err != ErrInvalidResource {
		t.Fatalf("Expected adding permissions with empty resource to return ErrInvalidResource, but got: %v", err)
	}

	// Create test role first
	rbac.CreateRole("test-role", "Test Role", "")

	// Now test with empty action on existing role
	err = rbac.AddRolePermissions("test-role", "resource", []string{"read", ""})
	if err != ErrInvalidAction {
		t.Fatalf("Expected adding permissions with an empty action to return ErrInvalidAction, but got: %v", err)
	}

	// Test with non-existent role
	err = rbac.AddRolePermissions("nonexistent", "resource", []string{"read"})
	if err != storage.ErrRoleNotFound {
		t.Fatalf("Expected adding permissions to non-existent role to return ErrRoleNotFound, but got: %v", err)
	}
}

func TestRBACHasPermissionEdgeCases(t *testing.T) {
	s := NewMemoryStorage()
	rbac := NewRBACService(s)

	// Create role with specific path permissions
	rbac.CreateRole("path-role", "Path Role", "")
	rbac.AddRolePermission("path-role", "api/users", "read")

	// Create user with the role
	rbac.AddUserRole("path-user", "path-role")

	// Test non-matching path patterns
	has, err := rbac.HasPermission("path-user", "api", "read")
	if err != nil || has {
		t.Fatalf("Expected permission check for parent path to fail, err: %v, has: %v", err, has)
	}

	has, err = rbac.HasPermission("path-user", "api/users/123/profile", "read")
	if err != nil || has {
		t.Fatalf("Expected permission check for child path without wildcard to fail, err: %v, has: %v", err, has)
	}

	// Now add wildcard permission
	rbac.AddRolePermission("path-role", "api/posts/*", "read")

	// Test matching child path
	has, err = rbac.HasPermission("path-user", "api/posts/123", "read")
	if err != nil || !has {
		t.Fatalf("Expected permission check for child path with wildcard to succeed, err: %v, has: %v", err, has)
	}

	// Test different action on wildcard path
	has, err = rbac.HasPermission("path-user", "api/posts/123", "write")
	if err != nil || has {
		t.Fatalf("Expected permission check for different action to fail, err: %v, has: %v", err, has)
	}
}
