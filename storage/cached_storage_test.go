package storage

import (
	"sync"
	"testing"
	"time"
)

// setupTestCachedStorage creates a cached storage with memory backend for testing
func setupTestCachedStorage(t *testing.T) *CachedStorage {
	memoryStorage := NewMemoryStorage()
	config := DefaultCacheConfig()
	// Use shorter TTL for faster testing
	config.RoleCacheTTL = 100 * time.Millisecond
	config.UserRoleCacheTTL = 100 * time.Millisecond
	config.CleanupInterval = 50 * time.Millisecond

	storage := NewCachedStorage(memoryStorage, config)
	cachedStorage, ok := storage.(*CachedStorage)
	if !ok {
		t.Fatal("Expected CachedStorage type")
	}
	return cachedStorage
}

// setupTestCachedSQLStorage creates a cached storage with SQL backend for testing
func setupTestCachedSQLStorage(t *testing.T) *CachedStorage {
	sqlStorage := setupTestStorage(t)
	config := DefaultCacheConfig()
	// Use shorter TTL for faster testing
	config.RoleCacheTTL = 100 * time.Millisecond
	config.UserRoleCacheTTL = 100 * time.Millisecond
	config.CleanupInterval = 50 * time.Millisecond

	storage := NewCachedStorage(sqlStorage, config)
	cachedStorage, ok := storage.(*CachedStorage)
	if !ok {
		t.Fatal("Expected CachedStorage type")
	}
	return cachedStorage
}

func TestCachedStorageRoleCaching(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role
	role := NewRole("admin", "Administrator", "System administrator")
	err := cs.CreateRole(role)
	if err != nil {
		t.Fatalf("Expected successful role creation, but got error: %v", err)
	}

	// First access should be a cache miss
	_, err = cs.GetRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role retrieval, but got error: %v", err)
	}

	roleHits, roleMisses, _, _ := cs.Stats()
	if roleMisses != 1 || roleHits != 0 {
		t.Fatalf("Expected 0 hits and 1 miss, but got %d hits and %d misses", roleHits, roleMisses)
	}

	// Second access should be a cache hit
	_, err = cs.GetRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role retrieval, but got error: %v", err)
	}

	roleHits, roleMisses, _, _ = cs.Stats()
	if roleMisses != 1 || roleHits != 1 {
		t.Fatalf("Expected 1 hit and 1 miss, but got %d hits and %d misses", roleHits, roleMisses)
	}

	// Wait for the cache to expire
	time.Sleep(150 * time.Millisecond)

	// This should be another cache miss
	_, err = cs.GetRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role retrieval, but got error: %v", err)
	}

	roleHits, roleMisses, _, _ = cs.Stats()
	if roleMisses != 2 || roleHits != 1 {
		t.Fatalf("Expected 1 hit and 2 misses after expiration, but got %d hits and %d misses", roleHits, roleMisses)
	}
}

func TestCachedStorageUserRoleCaching(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role and assign to user
	cs.CreateRole(NewRole("admin", "Administrator", ""))
	cs.AddUserRole("user1", "admin")

	// First access should be a cache miss
	roles, err := cs.GetUserRoles("user1")
	if err != nil {
		t.Fatalf("Expected successful user roles retrieval, but got error: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("Expected user roles to be ['admin'], but got: %v", roles)
	}

	_, _, userRoleHits, userRoleMisses := cs.Stats()
	if userRoleMisses != 1 || userRoleHits != 0 {
		t.Fatalf("Expected 0 hits and 1 miss, but got %d hits and %d misses", userRoleHits, userRoleMisses)
	}

	// Second access should be a cache hit
	_, err = cs.GetUserRoles("user1")
	if err != nil {
		t.Fatalf("Expected successful user roles retrieval, but got error: %v", err)
	}

	_, _, userRoleHits, userRoleMisses = cs.Stats()
	if userRoleMisses != 1 || userRoleHits != 1 {
		t.Fatalf("Expected 1 hit and 1 miss, but got %d hits and %d misses", userRoleHits, userRoleMisses)
	}

	// Wait for the cache to expire
	time.Sleep(150 * time.Millisecond)

	// This should be another cache miss
	_, err = cs.GetUserRoles("user1")
	if err != nil {
		t.Fatalf("Expected successful user roles retrieval, but got error: %v", err)
	}

	_, _, userRoleHits, userRoleMisses = cs.Stats()
	if userRoleMisses != 2 || userRoleHits != 1 {
		t.Fatalf("Expected 1 hit and 2 misses after expiration, but got %d hits and %d misses", userRoleHits, userRoleMisses)
	}
}

func TestCachedStorageRoleUpdates(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role
	role := NewRole("admin", "Administrator", "")
	cs.CreateRole(role)

	// Get it once to cache it
	role, _ = cs.GetRole("admin")
	if role.Name != "Administrator" {
		t.Fatalf("Expected role name to be 'Administrator', but got: %s", role.Name)
	}

	// Update the role
	role.Name = "Super Admin"
	err := cs.UpdateRole(role)
	if err != nil {
		t.Fatalf("Expected successful role update, but got error: %v", err)
	}

	// Get it again - should get the updated version from cache
	updatedRole, _ := cs.GetRole("admin")
	if updatedRole.Name != "Super Admin" {
		t.Fatalf("Expected updated role name to be 'Super Admin', but got: %s", updatedRole.Name)
	}

	roleHits, _, _, _ := cs.Stats()
	if roleHits != 1 {
		t.Fatalf("Expected 1 hit after update, but got %d hits", roleHits)
	}
}

func TestCachedStorageRoleDeletion(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role
	role := NewRole("admin", "Administrator", "")
	cs.CreateRole(role)

	// Get it once to cache it
	cs.GetRole("admin")

	// Delete the role
	err := cs.DeleteRole("admin")
	if err != nil {
		t.Fatalf("Expected successful role deletion, but got error: %v", err)
	}

	// Try to get it again - should return error
	_, err = cs.GetRole("admin")
	if err != ErrRoleNotFound {
		t.Fatalf("Expected ErrRoleNotFound after deletion, but got: %v", err)
	}

	// Create the role again
	cs.CreateRole(role)
	newRole, _ := cs.GetRole("admin")
	if newRole.Name != "Administrator" {
		t.Fatalf("Expected recreated role name to be 'Administrator', but got: %s", newRole.Name)
	}
}

func TestCachedStorageUserRoleModifications(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create roles
	cs.CreateRole(NewRole("admin", "Administrator", ""))
	cs.CreateRole(NewRole("user", "User", ""))

	// Add user role
	cs.AddUserRole("user1", "admin")

	// Get user roles to cache them
	roles, _ := cs.GetUserRoles("user1")
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("Expected user roles to be ['admin'], but got: %v", roles)
	}

	// Add another role
	cs.AddUserRole("user1", "user")

	// Get roles again - should reflect the new role due to cache invalidation
	roles, _ = cs.GetUserRoles("user1")
	if len(roles) != 2 {
		t.Fatalf("Expected user to have 2 roles after addition, but got: %v", roles)
	}

	// Check stats - should have had one hit and another miss (after invalidation)
	_, _, userRoleHits, userRoleMisses := cs.Stats()
	if userRoleMisses != 2 || userRoleHits != 0 {
		t.Fatalf("Expected 0 hits and 2 misses, but got %d hits and %d misses", userRoleHits, userRoleMisses)
	}

	// Remove a role
	cs.RemoveUserRole("user1", "user")

	// Get roles again - should reflect the removal due to cache invalidation
	roles, _ = cs.GetUserRoles("user1")
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("Expected user roles to be ['admin'] after removal, but got: %v", roles)
	}
}

func TestCachedStoragePermissions(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role
	role := NewRole("admin", "Administrator", "")
	cs.CreateRole(role)

	// Add permission
	err := cs.AddRolePermission("admin", "users", "read")
	if err != nil {
		t.Fatalf("Expected successful permission addition, but got error: %v", err)
	}

	// Check the permission - not cached yet
	has, err := cs.HasPermission("admin", "users", "read")
	if err != nil || !has {
		t.Fatalf("Expected permission to be granted, err: %v, has: %v", err, has)
	}

	// Get the role to verify it's cached
	role, _ = cs.GetRole("admin")
	if len(role.Permissions["users"]) != 1 || role.Permissions["users"][0] != "read" {
		t.Fatalf("Expected role to have users:read permission, but got: %v", role.Permissions)
	}

	// Add another permission
	cs.AddRolePermission("admin", "users", "write")

	// Check both permissions - should work despite cache invalidation
	has, _ = cs.HasPermission("admin", "users", "read")
	if !has {
		t.Fatal("Expected role to still have read permission after adding write")
	}

	has, _ = cs.HasPermission("admin", "users", "write")
	if !has {
		t.Fatal("Expected role to have write permission after adding it")
	}

	// Remove the permission
	cs.RemoveRolePermission("admin", "users")

	// Check permissions again - should reflect removal
	has, _ = cs.HasPermission("admin", "users", "read")
	if has {
		t.Fatal("Expected permission to be removed, but it's still granted")
	}
}

func TestCachedStorageClearCache(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Set up some data
	cs.CreateRole(NewRole("admin", "Administrator", ""))
	cs.CreateRole(NewRole("user", "User", ""))
	cs.AddUserRole("user1", "admin")
	cs.AddUserRole("user1", "user")

	// Access the data to cache it
	cs.GetRole("admin")
	cs.GetRole("user")
	cs.GetUserRoles("user1")

	// Check stats
	_, roleMisses, _, userRoleMisses := cs.Stats()
	if roleMisses == 0 || userRoleMisses == 0 {
		t.Fatal("Expected some cache misses during setup")
	}

	// Clear the cache
	cs.ClearCache()

	// Check that cache size is reset
	roleCount, userRoleCount := cs.GetCacheSize()
	if roleCount != 0 || userRoleCount != 0 {
		t.Fatalf("Expected cache sizes to be reset to 0, but got role:%d, userRole:%d", roleCount, userRoleCount)
	}

	// Check that stats are reset
	roleHits, roleMisses, userRoleHits, userRoleMisses := cs.Stats()
	if roleHits != 0 || roleMisses != 0 || userRoleHits != 0 || userRoleMisses != 0 {
		t.Fatalf("Expected stats to be reset to 0, got hits:%d,%d misses:%d,%d",
			roleHits, userRoleHits, roleMisses, userRoleMisses)
	}

	// Access the data again - should be cache misses
	cs.GetRole("admin")
	cs.GetUserRoles("user1")

	roleHits, roleMisses, userRoleHits, userRoleMisses = cs.Stats()
	if roleHits != 0 || roleMisses != 1 || userRoleHits != 0 || userRoleMisses != 1 {
		t.Fatalf("Expected 0 hits and 1 miss after cache clear, but got hits:%d,%d misses:%d,%d",
			roleHits, userRoleHits, roleMisses, userRoleMisses)
	}
}

func TestCachedStorageExpiration(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role
	cs.CreateRole(NewRole("temp", "Temporary", ""))

	// Access it to cache it
	cs.GetRole("temp")

	// Wait for automatic cleanup to kick in
	time.Sleep(200 * time.Millisecond)

	// Check cache size - should be automatically reduced
	roleCount, _ := cs.GetCacheSize()
	if roleCount != 0 {
		t.Fatalf("Expected role cache count to be 0 after expiration, but got: %d", roleCount)
	}

	// Access again - should be a cache miss
	cs.GetRole("temp")

	_, roleMisses, _, _ := cs.Stats()
	if roleMisses != 2 { // Initial miss + miss after expiration
		t.Fatalf("Expected 2 misses after expiration, but got: %d", roleMisses)
	}
}

func TestCachedStorageWithSQLStorage(t *testing.T) {
	cs := setupTestCachedSQLStorage(t)
	defer cs.Close()

	// Create a role
	role := NewRole("sql-cached", "SQL Cached", "Testing with SQL backend")
	cs.CreateRole(role)

	// First access - cache miss
	role, _ = cs.GetRole("sql-cached")
	if role.Name != "SQL Cached" {
		t.Fatalf("Expected role name 'SQL Cached', but got: %s", role.Name)
	}

	roleHits, roleMisses, _, _ := cs.Stats()
	if roleHits != 0 || roleMisses != 1 {
		t.Fatalf("Expected 0 hits and 1 miss, but got %d hits and %d misses", roleHits, roleMisses)
	}

	// Second access - cache hit
	role, _ = cs.GetRole("sql-cached")
	if role.Name != "SQL Cached" {
		t.Fatalf("Expected role name 'SQL Cached', but got: %s", role.Name)
	}

	roleHits, roleMisses, _, _ = cs.Stats()
	if roleHits != 1 || roleMisses != 1 {
		t.Fatalf("Expected 1 hit and 1 miss, but got %d hits and %d misses", roleHits, roleMisses)
	}

	// Update role
	role.Name = "Updated SQL Role"
	cs.UpdateRole(role)

	// Access after update - should get updated version
	updatedRole, _ := cs.GetRole("sql-cached")
	if updatedRole.Name != "Updated SQL Role" {
		t.Fatalf("Expected updated role name 'Updated SQL Role', but got: %s", updatedRole.Name)
	}

	// Verify it's still a cache hit
	roleHits, roleMisses, _, _ = cs.Stats()
	if roleHits != 2 || roleMisses != 1 {
		t.Fatalf("Expected 2 hits and 1 miss after update, but got %d hits and %d misses", roleHits, roleMisses)
	}
}

func TestCachedStorageConcurrency(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Setup roles and users
	cs.CreateRole(NewRole("role1", "Role 1", ""))
	cs.CreateRole(NewRole("role2", "Role 2", ""))
	cs.AddUserRole("user1", "role1")
	cs.AddUserRole("user2", "role2")

	// Run concurrent operations
	var wg sync.WaitGroup
	wg.Add(4)

	// Goroutine 1: Get roles
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cs.GetRole("role1")
		}
	}()

	// Goroutine 2: Get user roles
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cs.GetUserRoles("user1")
		}
	}()

	// Goroutine 3: Update roles
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			role, _ := cs.GetRole("role2")
			role.Description = "Updated " + time.Now().String()
			cs.UpdateRole(role)
			time.Sleep(5 * time.Millisecond) // Small delay to increase chance of race conditions
		}
	}()

	// Goroutine 4: Clear cache occasionally
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			time.Sleep(20 * time.Millisecond)
			cs.ClearCache()
		}
	}()

	wg.Wait()

	// If we got this far without panicking, the test passes
	// We could also verify the stats if needed
	roleHits, roleMisses, userRoleHits, userRoleMisses := cs.Stats()
	t.Logf("After concurrent operations - roleHits: %d, roleMisses: %d, userRoleHits: %d, userRoleMisses: %d",
		roleHits, roleMisses, userRoleHits, userRoleMisses)
}

func TestCachedStorageMaxSize(t *testing.T) {
	// Create storage with very small max cache size
	memoryStorage := NewMemoryStorage()
	config := DefaultCacheConfig()
	config.MaxRoleCacheSize = 2
	config.MaxUserRoleCacheSize = 2

	cs := NewCachedStorage(memoryStorage, config).(*CachedStorage)
	defer cs.Close()

	// Create more roles than the cache can hold
	cs.CreateRole(NewRole("role1", "Role 1", ""))
	cs.CreateRole(NewRole("role2", "Role 2", ""))
	cs.CreateRole(NewRole("role3", "Role 3", ""))
	cs.CreateRole(NewRole("role4", "Role 4", ""))

	// Access all roles to try to cache them
	cs.GetRole("role1")
	cs.GetRole("role2")
	roleCount, _ := cs.GetCacheSize()
	if roleCount > 2 {
		t.Fatalf("Expected role cache count to not exceed max size (2), but got: %d", roleCount)
	}

	// Try to access more roles
	cs.GetRole("role3")
	cs.GetRole("role4")
	roleCount, _ = cs.GetCacheSize()
	if roleCount > 2 {
		t.Fatalf("Expected role cache count to still not exceed max size (2), but got: %d", roleCount)
	}

	// Similar test for user roles
	cs.AddUserRole("user1", "role1")
	cs.AddUserRole("user2", "role1")
	cs.AddUserRole("user3", "role1")
	cs.AddUserRole("user4", "role1")

	// Access all user roles to try to cache them
	cs.GetUserRoles("user1")
	cs.GetUserRoles("user2")
	_, userRoleCount := cs.GetCacheSize()
	if userRoleCount > 2 {
		t.Fatalf("Expected user role cache count to not exceed max size (2), but got: %d", userRoleCount)
	}

	// Try to access more user roles
	cs.GetUserRoles("user3")
	cs.GetUserRoles("user4")
	_, userRoleCount = cs.GetCacheSize()
	if userRoleCount > 2 {
		t.Fatalf("Expected user role cache count to still not exceed max size (2), but got: %d", userRoleCount)
	}
}

func TestCachedStorageAsyncPermissionCaching(t *testing.T) {
	cs := setupTestCachedStorage(t)
	defer cs.Close()

	// Create a role with permission
	role := NewRole("async-test", "Async Test", "")
	role.Permissions = map[string][]string{
		"resource": {"action"},
	}
	cs.CreateRole(role)

	// Check permission without caching the role first
	has, err := cs.HasPermission("async-test", "resource", "action")
	if !has || err != nil {
		t.Fatalf("Expected permission to be granted, has: %v, err: %v", has, err)
	}

	// Give a bit of time for the async caching to complete
	time.Sleep(50 * time.Millisecond)

	// Now the role should be cached, check stats
	_, roleMisses, _, _ := cs.Stats()
	// We expect 0 explicit hits since HasPermission uses the persistent storage directly first
	if roleMisses != 0 {
		t.Fatalf("Expected no explicit role misses due to async caching, but got: %d", roleMisses)
	}

	// Access the role directly now - should be a cache hit
	_, err = cs.GetRole("async-test")
	if err != nil {
		t.Fatalf("Expected role to be cached after HasPermission, but got error: %v", err)
	}

	roleHits, _, _, _ := cs.Stats()
	if roleHits != 1 {
		t.Fatalf("Expected 1 role hit after async caching, but got: %d", roleHits)
	}
}

func BenchmarkCachedStorage_GetRole(b *testing.B) {
	memoryStorage := NewMemoryStorage()
	config := DefaultCacheConfig()
	storage := NewCachedStorage(memoryStorage, config).(*CachedStorage)
	defer storage.Close()

	// Set up test data
	storage.CreateRole(NewRole("bench-role", "Bench Role", "For benchmarking"))

	// Reset the timer
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		storage.GetRole("bench-role")
	}
}

func BenchmarkCachedStorage_GetUserRoles(b *testing.B) {
	memoryStorage := NewMemoryStorage()
	config := DefaultCacheConfig()
	storage := NewCachedStorage(memoryStorage, config).(*CachedStorage)
	defer storage.Close()

	// Set up test data
	storage.CreateRole(NewRole("bench-role-1", "Role 1", ""))
	storage.CreateRole(NewRole("bench-role-2", "Role 2", ""))
	storage.AddUserRole("bench-user", "bench-role-1")
	storage.AddUserRole("bench-user", "bench-role-2")

	// Reset the timer
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		storage.GetUserRoles("bench-user")
	}
}

func BenchmarkCachedStorage_HasPermission(b *testing.B) {
	memoryStorage := NewMemoryStorage()
	config := DefaultCacheConfig()
	storage := NewCachedStorage(memoryStorage, config).(*CachedStorage)
	defer storage.Close()

	// Set up test data
	role := NewRole("bench-role", "Bench Role", "")
	role.Permissions = map[string][]string{
		"resource": {"read", "write", "delete"},
	}
	storage.CreateRole(role)

	// Reset the timer
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		storage.HasPermission("bench-role", "resource", "read")
	}
}

func BenchmarkDirectStorage_GetRole(b *testing.B) {
	storage := NewMemoryStorage()

	// Set up test data
	storage.CreateRole(NewRole("bench-role", "Bench Role", "For benchmarking"))

	// Reset the timer
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		storage.GetRole("bench-role")
	}
}

func TestCachedSQLStoragePerformanceGain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SQL performance test in short mode")
	}

	// 创建不带缓存的SQL存储
	directSQL := setupTestStorage(t)

	// 创建带缓存的SQL存储
	cachedSQL := setupTestCachedSQLStorage(t)

	// 设置测试数据
	role := NewRole("perf-test", "Performance Test", "")
	directSQL.CreateRole(role)

	// 测试性能差异
	iterations := 100
	start := time.Now()
	for i := 0; i < iterations; i++ {
		directSQL.GetRole("perf-test")
	}
	directDuration := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		cachedSQL.GetRole("perf-test")
	}
	cachedDuration := time.Since(start)

	// 缓存应明显快于直接SQL访问
	t.Logf("Direct SQL: %v, Cached SQL: %v, Speedup: %.2fx",
		directDuration, cachedDuration, float64(directDuration)/float64(cachedDuration))

	if cachedDuration*2 > directDuration {
		t.Errorf("Expected at least 2x speedup with cache, but got only %.2fx",
			float64(directDuration)/float64(cachedDuration))
	}
}
