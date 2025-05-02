package storage

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	_ "modernc.org/sqlite" // Pure Go SQLite driver
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite database: %v", err)
	}

	_, err = db.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	return db
}

// setupTestStorage creates a new SQLStorage instance with in-memory SQLite database
func setupTestStorage(t *testing.T) Storage {
	db := setupTestDB(t)
	storage, err := NewSQLStorage(db)
	if err != nil {
		t.Fatalf("Failed to create SQL storage: %v", err)
	}
	return storage
}

func TestSQLStorageRoleManagement(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create role
	role := NewRole("admin", "Administrator", "System administrator")
	err := storage.CreateRole(role)
	if err != nil {
		t.Fatalf("Expected successful role creation, but got error: %v", err)
	}

	// Create duplicate role
	err = storage.CreateRole(role)
	if err != ErrRoleAlreadyExists {
		t.Fatalf("Expected ErrRoleAlreadyExists when creating duplicate role, but got: %v", err)
	}

	// Get role
	retrievedRole, err := storage.GetRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role retrieval, but got error: %v", err)
	}
	if retrievedRole.ID != "admin" || retrievedRole.Name != "Administrator" {
		t.Fatalf("Expected retrieved role to match created role, but got: %+v", retrievedRole)
	}

	// Get non-existent role
	_, err = storage.GetRole("nonexistent")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when getting non-existent role, but got: %v", err)
	}

	// Update role
	retrievedRole.Name = "Super Admin"
	err = storage.UpdateRole(retrievedRole)
	if err != nil {
		t.Fatalf("Expected successful role update, but got error: %v", err)
	}

	// Verify update
	updatedRole, _ := storage.GetRole("admin")
	if updatedRole.Name != "Super Admin" {
		t.Fatalf("Expected role name to be updated to 'Super Admin', but got: %s", updatedRole.Name)
	}

	// Verify UpdatedAt was changed
	initialTime := role.UpdatedAt
	time.Sleep(time.Millisecond * 5) // Ensure time difference
	storage.UpdateRole(updatedRole)
	finalRole, _ := storage.GetRole("admin")
	if !finalRole.UpdatedAt.After(initialTime) {
		t.Fatal("Expected UpdatedAt time to be updated after role update")
	}

	// Update non-existent role
	nonexistentRole := NewRole("nonexistent", "Nonexistent", "")
	err = storage.UpdateRole(nonexistentRole)
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when updating non-existent role, but got: %v", err)
	}

	// List roles
	roles, err := storage.ListRoles()
	if err != nil {
		t.Fatalf("Expected successful role listing, but got error: %v", err)
	}
	if len(roles) != 1 {
		t.Fatalf("Expected role count to be 1, but got: %d", len(roles))
	}

	// Delete role
	err = storage.DeleteRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role deletion, but got error: %v", err)
	}

	// Verify deletion
	roles, _ = storage.ListRoles()
	if len(roles) != 0 {
		t.Fatalf("Expected role count after deletion to be 0, but got: %d", len(roles))
	}

	// Delete non-existent role
	err = storage.DeleteRole("nonexistent")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when deleting non-existent role, but got: %v", err)
	}
}

func TestSQLStorageUserRoleManagement(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create roles
	storage.CreateRole(NewRole("admin", "Administrator", ""))
	storage.CreateRole(NewRole("user", "User", ""))

	// Add user role
	err := storage.AddUserRole("user1", "admin")
	if err != nil {
		t.Fatalf("Expected successful user role assignment, but got error: %v", err)
	}

	// Add non-existent role
	err = storage.AddUserRole("user1", "nonexistent")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when adding non-existent role, but got: %v", err)
	}

	// Add duplicate user role
	err = storage.AddUserRole("user1", "admin")
	if err != ErrUserAlreadyHasRole {
		t.Fatalf("Expected ErrUserAlreadyHasRole when adding duplicate role, but got: %v", err)
	}

	// Get user roles
	roles, err := storage.GetUserRoles("user1")
	if err != nil {
		t.Fatalf("Expected successful user role retrieval, but got error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("Expected user roles to be ['admin'], but got: %v", roles)
	}

	// Get roles for non-existent user (should return empty array without error)
	roles, err = storage.GetUserRoles("nonexistent")
	if err != nil || len(roles) != 0 {
		t.Fatalf("Expected empty role array for non-existent user without error, but got: %v, %v", roles, err)
	}

	// Remove user role
	err = storage.RemoveUserRole("user1", "admin")
	if err != nil {
		t.Fatalf("Expected successful user role removal, but got error: %v", err)
	}

	// Verify removal
	roles, _ = storage.GetUserRoles("user1")
	if len(roles) != 0 {
		t.Fatalf("Expected user role count after removal to be 0, but got: %d", len(roles))
	}

	// Remove non-existent user role
	err = storage.RemoveUserRole("user1", "admin")
	if err != ErrUserDoesNotHaveRole {
		t.Fatalf("Expected ErrUserDoesNotHaveRole when removing non-existent user role, but got: %v", err)
	}

	// Remove role from non-existent user
	err = storage.RemoveUserRole("nonexistent", "admin")
	if err != ErrUserDoesNotHaveRole {
		t.Fatalf("Expected ErrUserDoesNotHaveRole when removing role from non-existent user, but got: %v", err)
	}
}

func TestSQLStoragePermissionManagement(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create role
	storage.CreateRole(NewRole("admin", "Administrator", ""))

	// Add permission
	err := storage.AddRolePermission("admin", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission addition, but got error: %v", err)
	}

	// Add permission to non-existent role
	err = storage.AddRolePermission("nonexistent", "users", "read")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when adding permission to non-existent role, but got: %v", err)
	}

	// Verify permission
	has, err := storage.HasPermission("admin", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission check, but got error: %v", err)
	}
	if !has {
		t.Fatal("Expected role to have permission, but returned false")
	}

	// Verify non-existent permission
	has, err = storage.HasPermission("admin", "users", "write")
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}
	if has {
		t.Fatal("Expected role not to have this permission, but returned true")
	}

	// Verify permission for non-existent resource
	has, err = storage.HasPermission("admin", "posts", "read")
	if err != nil {
		t.Fatalf("Expected no error for non-existent resource, but got: %v", err)
	}
	if has {
		t.Fatal("Expected role not to have permission for non-existent resource, but returned true")
	}

	// Verify permission for non-existent role
	_, err = storage.HasPermission("nonexistent", "users", "read")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when checking permission for non-existent role, but got: %v", err)
	}

	// Remove permission
	err = storage.RemoveRolePermission("admin", "users")
	if err != nil {
		t.Fatalf("Expected successful permission removal, but got error: %v", err)
	}

	// Verify permission after removal
	has, _ = storage.HasPermission("admin", "users", "read")
	if has {
		t.Fatal("Expected permission to be removed, but returned true")
	}

	// Remove non-existent permission
	err = storage.RemoveRolePermission("admin", "nonexistent")
	if err != ErrPermissionNotFound {
		t.Fatalf("Expected ErrPermissionNotFound when removing non-existent permission, but got: %v", err)
	}

	// Remove permission from non-existent role
	err = storage.RemoveRolePermission("nonexistent", "users")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when removing permission from non-existent role, but got: %v", err)
	}
}

func TestSQLStorageDeleteRoleWithUserRoles(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create roles
	storage.CreateRole(NewRole("admin", "Administrator", ""))
	storage.CreateRole(NewRole("user", "User", ""))

	// Add user roles
	storage.AddUserRole("user1", "admin")
	storage.AddUserRole("user1", "user")
	storage.AddUserRole("user2", "admin")

	// Delete role
	err := storage.DeleteRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role deletion, but got error: %v", err)
	}

	// Verify user roles were removed (due to CASCADE constraint)
	roles1, _ := storage.GetUserRoles("user1")
	roles2, _ := storage.GetUserRoles("user2")

	if slices.Contains(roles1, "admin") {
		t.Fatal("Expected admin role to be removed from user1, but it still exists")
	}
	if len(roles1) != 1 || roles1[0] != "user" {
		t.Fatalf("Expected user1 to have only the 'user' role remaining, but got: %v", roles1)
	}
	if len(roles2) != 0 {
		t.Fatalf("Expected user2 to have no roles remaining, but got: %v", roles2)
	}
}

func TestSQLStorageAddDuplicatePermission(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create role
	storage.CreateRole(NewRole("admin", "Administrator", ""))

	// Add permission
	storage.AddRolePermission("admin", "users", "read")

	// Add duplicate permission (should succeed but not duplicate)
	err := storage.AddRolePermission("admin", "users", "read")
	if err != nil {
		t.Fatalf("Expected adding duplicate permission to succeed, but got error: %v", err)
	}

	// Get role
	role, _ := storage.GetRole("admin")

	// Verify permission was not duplicated
	actions := role.Permissions["users"]
	count := 0
	for _, a := range actions {
		if a == "read" {
			count++
		}
	}

	if count != 1 {
		t.Fatalf("Expected 'read' permission to appear only once (duplicate prevented), but it appears %d times", count)
	}
}

func TestSQLStorageNilPermissionsMap(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create a role without explicitly initializing its permissions map
	roleWithoutPermissions := &Role{
		ID:          "no-perms",
		Name:        "No Permissions",
		Description: "Role with nil permissions map",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		// Permissions is left nil
	}

	storage.CreateRole(roleWithoutPermissions)

	// Add permission - should initialize the map
	err := storage.AddRolePermission("no-perms", "resource", "action")
	if err != nil {
		t.Fatalf("Expected successful permission addition to role with nil permissions map, but got error: %v", err)
	}

	// Verify permission was added
	has, err := storage.HasPermission("no-perms", "resource", "action")
	if err != nil || !has {
		t.Fatalf("Expected permission to be successfully added and retrievable, err: %v, has: %v", err, has)
	}
}

func TestSQLStorageRoleWithPermissions(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create a role with pre-defined permissions
	roleWithPermissions := &Role{
		ID:          "with-perms",
		Name:        "With Permissions",
		Description: "Role with pre-defined permissions",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Permissions: map[string][]string{
			"users": {"read", "list"},
			"posts": {"read", "write", "delete"},
		},
	}

	storage.CreateRole(roleWithPermissions)

	// Verify permissions were stored correctly
	has, err := storage.HasPermission("with-perms", "users", "read")
	if err != nil || !has {
		t.Fatalf("Expected role to have 'users:read' permission, err: %v, has: %v", err, has)
	}

	has, err = storage.HasPermission("with-perms", "posts", "delete")
	if err != nil || !has {
		t.Fatalf("Expected role to have 'posts:delete' permission, err: %v, has: %v", err, has)
	}

	has, err = storage.HasPermission("with-perms", "users", "delete")
	if err != nil || has {
		t.Fatalf("Expected role not to have 'users:delete' permission, err: %v, has: %v", err, has)
	}

	// Remove permissions for a resource
	err = storage.RemoveRolePermission("with-perms", "users")
	if err != nil {
		t.Fatalf("Expected successful removal of permissions, but got: %v", err)
	}

	// Verify removal
	role, _ := storage.GetRole("with-perms")
	_, exists := role.Permissions["users"]
	if exists {
		t.Fatal("Expected 'users' resource to be removed from permissions, but it still exists")
	}

	// 'posts' resource should still exist
	_, exists = role.Permissions["posts"]
	if !exists {
		t.Fatal("Expected 'posts' resource to still exist in permissions, but it was removed")
	}
}

func TestSQLStorageMultipleUpdatesToRole(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create role
	role := NewRole("multi-update", "Original Name", "Original description")
	storage.CreateRole(role)

	// Multiple updates in sequence
	role.Name = "First Update"
	storage.UpdateRole(role)

	role.Description = "Updated description"
	storage.UpdateRole(role)

	role.Name = "Final Name"
	storage.UpdateRole(role)

	// Verify final state
	finalRole, err := storage.GetRole("multi-update")
	if err != nil {
		t.Fatalf("Expected successful role retrieval after multiple updates, but got error: %v", err)
	}

	if finalRole.Name != "Final Name" || finalRole.Description != "Updated description" {
		t.Fatalf("Role not updated correctly after multiple updates. Got: %+v", finalRole)
	}
}

func TestSQLStorageEdgeCases(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Test with empty roleID
	_, err := storage.GetRole("")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound when getting role with empty ID, but got: %v", err)
	}

	// Create role with empty permission lists
	role := NewRole("empty-perms", "Empty Permissions", "")
	role.Permissions = map[string][]string{
		"resource1": {},
		"resource2": {},
	}

	storage.CreateRole(role)

	// Check permission on resource with empty actions list
	has, err := storage.HasPermission("empty-perms", "resource1", "read")
	if err != nil || has {
		t.Fatalf("Expected permission check to return false for empty actions list, err: %v, has: %v", err, has)
	}

	// Remove all user roles
	storage.CreateRole(NewRole("multi-role", "Multi Role", ""))
	storage.AddUserRole("multi-user", "multi-role")
	storage.AddUserRole("multi-user", "empty-perms")

	// Verify roles were added
	roles, _ := storage.GetUserRoles("multi-user")
	if len(roles) != 2 {
		t.Fatalf("Expected user to have 2 roles, but got: %v", roles)
	}

	// Remove all roles one by one
	for _, roleID := range roles {
		storage.RemoveUserRole("multi-user", roleID)
	}

	// Verify all roles were removed
	roles, _ = storage.GetUserRoles("multi-user")
	if len(roles) != 0 {
		t.Fatalf("Expected all user roles to be removed, but still has: %v", roles)
	}
}

func TestSQLStorageDeleteRolePermissions(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create a role with permissions
	role := NewRole("test-role", "Test Role", "")
	storage.CreateRole(role)
	storage.AddRolePermission("test-role", "resource1", "action1")
	storage.AddRolePermission("test-role", "resource2", "action2")

	// Delete the role
	err := storage.DeleteRole("test-role")
	if err != nil {
		t.Fatalf("Expected successful role deletion, but got error: %v", err)
	}

	// Verify permissions are removed
	_, err = storage.GetRole("test-role")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound after deletion, but got: %v", err)
	}

	// Verify permissions are not accessible
	newRole := NewRole("test-role", "New Test Role", "")
	err = storage.CreateRole(newRole)
	if err != nil {
		t.Fatalf("Expected to create new role with same ID after deletion, but got: %v", err)
	}

	// Check if the new role has the old permissions
	hasOldPerm, _ := storage.HasPermission("test-role", "resource1", "action1")
	if hasOldPerm {
		t.Fatal("New role should not have permissions from deleted role")
	}
}

// Additional SQL-specific tests

func TestSQLStorageDatabaseConnection(t *testing.T) {
	// Test with nil database connection
	_, err := NewSQLStorage(nil)
	if err == nil {
		t.Fatal("Expected error when creating storage with nil DB connection, but got nil")
	}
}

func TestSQLStorageTransactionRollback(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create a role to work with
	roleID := "transaction-test"
	role := NewRole(roleID, "Transaction Test", "")
	storage.CreateRole(role)

	// Get the actual SQL storage implementation
	sqlStorage, ok := storage.(*SQLStorage)
	if !ok {
		t.Fatal("Expected SQLStorage type")
	}

	// Replace the DB with a closed one to force transaction errors
	originalDB := sqlStorage.db
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // Close it deliberately to cause errors

	sqlStorage.db = db
	defer func() {
		// Restore the original DB to ensure proper cleanup
		sqlStorage.db = originalDB
	}()

	// Now operations should fail
	err = sqlStorage.AddRolePermission(roleID, "resource", "action")
	if err == nil {
		t.Fatal("Expected error when working with closed DB, but got nil")
	}

	err = sqlStorage.RemoveRolePermission(roleID, "resource")
	if err == nil {
		t.Fatal("Expected error when working with closed DB, but got nil")
	}

	err = sqlStorage.DeleteRole(roleID)
	if err == nil {
		t.Fatal("Expected error when working with closed DB, but got nil")
	}
}

func TestSQLStorageJSONSerialization(t *testing.T) {
	storage := setupTestStorage(t)
	defer storage.Close()

	// Create role with special characters in permissions
	roleWithSpecialChars := NewRole("special", "Special", "")
	roleWithSpecialChars.Permissions = map[string][]string{
		"resource/with/path":     {"read", "write"},
		"resource-with-hyphens":  {"action1", "action2"},
		"resource.with.dots":     {"delete"},
		"resource with spaces":   {"update"},
		"resource\"with\"quotes": {"execute"},
	}

	err := storage.CreateRole(roleWithSpecialChars)
	if err != nil {
		t.Fatalf("Failed to create role with special characters: %v", err)
	}

	// Retrieve and verify
	retrieved, err := storage.GetRole("special")
	if err != nil {
		t.Fatalf("Failed to get role with special characters: %v", err)
	}

	// Check all permissions were correctly serialized and deserialized
	for resource, expectedActions := range roleWithSpecialChars.Permissions {
		actualActions, exists := retrieved.Permissions[resource]
		if !exists {
			t.Fatalf("Resource %q missing from retrieved permissions", resource)
		}

		for _, expectedAction := range expectedActions {
			if !slices.Contains(actualActions, expectedAction) {
				t.Fatalf("Action %q not found in resource %q actions: %v",
					expectedAction, resource, actualActions)
			}
		}
	}
}

func TestSQLStorageQueryErrors(t *testing.T) {
	// This test checks behavior with invalid SQL queries
	db := setupTestDB(t)
	defer db.Close()

	// Create a table with a different schema to cause SQL errors
	_, err := db.Exec(`
        CREATE TABLE guardian_roles (
            id INTEGER PRIMARY KEY,  -- Different schema (INTEGER instead of VARCHAR)
            name TEXT
        )
    `)
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// Create storage
	storage, err := NewSQLStorage(db)
	if err != nil {
		t.Fatalf("Failed to create SQL storage with custom schema: %v", err)
	}

	// Attempt operations that should now fail due to schema mismatch
	role := NewRole("test", "Test", "")
	err = storage.CreateRole(role)
	if err == nil {
		t.Fatal("Expected error when creating role with mismatched schema, but got nil")
	}
}

func TestCreateSQLiteStorage(t *testing.T) {
	tempFile := t.TempDir() + "/guardian_test.db"

	storage, err := CreateSQLiteStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage.Close()

	// Verify that the storage is working correctly
	role := NewRole("sqlite-test", "SQLite Test", "Testing CreateSQLiteStorage method")
	if err := storage.CreateRole(role); err != nil {
		t.Fatalf("Failed to create role with SQLite storage: %v", err)
	}

	// Verify that the role can be retrieved correctly
	retrievedRole, err := storage.GetRole("sqlite-test")
	if err != nil {
		t.Fatalf("Failed to retrieve role with SQLite storage: %v", err)
	}
	if retrievedRole.Name != "SQLite Test" {
		t.Fatalf("Expected role name 'SQLite Test', but got: %s", retrievedRole.Name)
	}
	if retrievedRole.Description != "Testing CreateSQLiteStorage method" {
		t.Fatalf("Expected role description 'Testing CreateSQLiteStorage method', but got: %s", retrievedRole.Description)
	}

	// Checks if the foreign key constraint is enabled in SQLite
	testRoleID := "cascade-test"
	userID := "test-user"

	testRole := NewRole(testRoleID, "Cascade Test", "Testing cascade delete")
	if err := storage.CreateRole(testRole); err != nil {
		t.Fatalf("Failed to create role for cascade test: %v", err)
	}

	if err := storage.AddUserRole(userID, testRoleID); err != nil {
		t.Fatalf("Failed to add user role for cascade test: %v", err)
	}

	// Delete the role, which should trigger cascade delete
	if err := storage.DeleteRole(testRoleID); err != nil {
		t.Fatalf("Failed to delete role for cascade test: %v", err)
	}

	// Verify that the user role has been cascade deleted
	userRoles, err := storage.GetUserRoles(userID)
	if err != nil {
		t.Fatalf("Failed to get user roles after cascade delete: %v", err)
	}

	if slices.Contains(userRoles, testRoleID) {
		t.Fatalf("Expected role %s to be deleted from user %s, but it still exists", testRoleID, userID)
	}
}

func TestCreateSQLiteStorageConnectionReuse(t *testing.T) {
	// Create a temporary SQLite database file
	tempFile := t.TempDir() + "/reuse_test.db"

	storage1, err := CreateSQLiteStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to create first SQLite storage: %v", err)
	}

	// Create test role
	role := NewRole("reuse-test", "Reuse Test", "")
	if err := storage1.CreateRole(role); err != nil {
		t.Fatalf("Failed to create role in first storage: %v", err)
	}

	// Close the first storage
	storage1.Close()

	// Create second storage instance, connecting to the same file
	storage2, err := CreateSQLiteStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to create second SQLite storage: %v", err)
	}
	defer storage2.Close()

	// Should be able to retrieve the role created by the first storage
	retrievedRole, err := storage2.GetRole("reuse-test")
	if err != nil {
		t.Fatalf("Failed to retrieve role from second storage instance: %v", err)
	}

	if retrievedRole.Name != "Reuse Test" {
		t.Fatalf("Expected role name to be 'Reuse Test', but got: %s", retrievedRole.Name)
	}
}

func TestSQLiteForeignKeyEnforcement(t *testing.T) {
	// Create a temporary SQLite database file
	tempFile := t.TempDir() + "/fk_test.db"

	storage, err := CreateSQLiteStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to create SQLite storage: %v", err)
	}
	defer storage.Close()

	// Create a role with foreign key constraints
	roleID := "fk-test"
	role := NewRole(roleID, "FK Test", "")
	if err := storage.CreateRole(role); err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	// Create users and assign roles
	userIDs := []string{"user1", "user2", "user3"}
	for _, userID := range userIDs {
		if err := storage.AddUserRole(userID, roleID); err != nil {
			t.Fatalf("Failed to add user role for %s: %v", userID, err)
		}
	}

	// Delete the role, which should trigger cascade delete
	if err := storage.DeleteRole(roleID); err != nil {
		t.Fatalf("Failed to delete role: %v", err)
	}

	// Verify that all user roles have been deleted
	for _, userID := range userIDs {
		roles, err := storage.GetUserRoles(userID)
		if err != nil {
			t.Fatalf("Failed to get roles for user %s: %v", userID, err)
		}

		if len(roles) > 0 {
			t.Fatalf("Expected no roles for user %s after cascade delete, but got: %v", userID, roles)
		}
	}
}
