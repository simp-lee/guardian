package storage

import (
	"sync"
	"sync/atomic"
	"time"
)

// CachedStorage wraps a persistent Storage implementation with an in-memory cache
// to improve performance for frequently accessed data.
type CachedStorage struct {
	persistent Storage // The underlying persistent storage
	cache      Storage // Memory-based cache (using MemoryStorage)
	config     CacheConfig

	roleTTLs     sync.Map // roleID -> time.Time
	userRoleTTLs sync.Map // userID -> time.Time

	stopCleanup chan struct{} // For stopping background goroutines

	stats struct {
		roleHits       int64
		roleMisses     int64
		userRoleHits   int64
		userRoleMisses int64
	}

	roleCacheCount     int
	userRoleCacheCount int
	countMutex         sync.RWMutex
}

func NewCachedStorage(persistent Storage, config CacheConfig) Storage {
	cs := &CachedStorage{
		persistent:  persistent,
		cache:       NewMemoryStorage(), // Use MemoryStorage for caching
		config:      config,
		stopCleanup: make(chan struct{}),
	}

	go cs.cleanup()
	return cs
}

// cleanup periodically removes expired items from the cache.
func (cs *CachedStorage) cleanup() {
	ticker := time.NewTicker(cs.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cs.cleanExpiredCache()
		case <-cs.stopCleanup:
			return
		}
	}
}

// cleanExpiredCache removes all expired items from the cache.
func (cs *CachedStorage) cleanExpiredCache() {
	now := time.Now()

	// Clean expired role cache entries
	cs.roleTTLs.Range(func(key, value any) bool {
		roleID := key.(string)
		expireTime := value.(time.Time)

		if now.After(expireTime) {
			err := cs.cache.DeleteRole(roleID)
			cs.roleTTLs.Delete(roleID)

			if err == nil {
				cs.countMutex.Lock()
				if cs.roleCacheCount > 0 {
					cs.roleCacheCount--
				}
				cs.countMutex.Unlock()
			}
		}
		return true
	})

	// Clean expired user-role relationships
	cs.userRoleTTLs.Range(func(key, value any) bool {
		userID := key.(string)
		expireTime := value.(time.Time)

		if now.After(expireTime) {
			// For user roles, we need to invalidate by removing all the user's roles
			// First get the roles so we can remove them one by one
			if roles, err := cs.cache.GetUserRoles(userID); err == nil {
				for _, roleID := range roles {
					cs.cache.RemoveUserRole(userID, roleID)
				}
			}
			cs.userRoleTTLs.Delete(userID)
			// Decrement count since the user entry (controlled by TTL) is removed
			cs.countMutex.Lock()
			if cs.userRoleCacheCount > 0 {
				cs.userRoleCacheCount--
			}
			cs.countMutex.Unlock()
		}
		return true
	})
}

// isRoleCached checks if a role is cached and not expired.
func (cs *CachedStorage) isRoleCached(roleID string) bool {
	if !cs.config.EnableRoleCache {
		return false
	}

	value, exists := cs.roleTTLs.Load(roleID)
	if !exists {
		return false
	}

	expireTime := value.(time.Time)
	return time.Now().Before(expireTime)
}

// isUserRoleCached checks if a user's roles are cached and not expired.
func (cs *CachedStorage) isUserRoleCached(userID string) bool {
	if !cs.config.EnableUserRoleCache {
		return false
	}

	value, exists := cs.userRoleTTLs.Load(userID)
	if !exists {
		return false
	}

	expireTime := value.(time.Time)
	return time.Now().Before(expireTime)
}

// updateRoleTTL sets or updates the expiration time for a cached role.
func (cs *CachedStorage) updateRoleTTL(roleID string) {
	if cs.config.EnableRoleCache {
		if cs.incrementRoleCacheCount() {
			expireTime := time.Now().Add(cs.config.RoleCacheTTL)
			cs.roleTTLs.Store(roleID, expireTime)
		}
	}
}

// updateUserRoleTTL sets or updates the expiration time for a cached user's roles.
func (cs *CachedStorage) updateUserRoleTTL(userID string) {
	if cs.config.EnableUserRoleCache {
		if cs.incrementUserRoleCacheCount() {
			expireTime := time.Now().Add(cs.config.UserRoleCacheTTL)
			cs.userRoleTTLs.Store(userID, expireTime)
		}
	}
}

// invalidateRoleCache removes a role from the cache.
func (cs *CachedStorage) invalidateRoleCache(roleID string) {
	if cs.config.EnableRoleCache {
		err := cs.cache.DeleteRole(roleID)
		cs.roleTTLs.Delete(roleID)
		if err == nil {
			cs.countMutex.Lock()
			if cs.roleCacheCount > 0 {
				cs.roleCacheCount--
			}
			cs.countMutex.Unlock()
		}
	}
}

// invalidateUserRoleCache removes a user's roles from the cache.
func (cs *CachedStorage) invalidateUserRoleCache(userID string) {
	if cs.config.EnableUserRoleCache {
		// Remove the TTL entry first to mark this cache as invalid
		cs.userRoleTTLs.Delete(userID)

		// Get the roles so we can remove them one by one
		roles, err := cs.cache.GetUserRoles(userID)
		if err == nil && len(roles) > 0 {
			for _, roleID := range roles {
				cs.cache.RemoveUserRole(userID, roleID)
			}
		}

		cs.countMutex.Lock()
		if cs.userRoleCacheCount > 0 {
			cs.userRoleCacheCount--
		}
		cs.countMutex.Unlock()
	}
}

func (cs *CachedStorage) incrementRoleCacheCount() bool {
	if cs.config.MaxRoleCacheSize <= 0 {
		return true
	}

	cs.countMutex.Lock()
	defer cs.countMutex.Unlock()

	if cs.roleCacheCount >= cs.config.MaxRoleCacheSize {
		return false
	}

	cs.roleCacheCount++
	return true
}

func (cs *CachedStorage) incrementUserRoleCacheCount() bool {
	if cs.config.MaxUserRoleCacheSize <= 0 {
		return true
	}

	cs.countMutex.Lock()
	defer cs.countMutex.Unlock()

	if cs.userRoleCacheCount >= cs.config.MaxUserRoleCacheSize {
		return false
	}

	cs.userRoleCacheCount++
	return true
}

func (cs *CachedStorage) CreateRole(role *Role) error {
	return cs.persistent.CreateRole(role)
}

func (cs *CachedStorage) GetRole(roleID string) (*Role, error) {
	if cs.isRoleCached(roleID) {
		role, err := cs.cache.GetRole(roleID)
		if err == nil {
			atomic.AddInt64(&cs.stats.roleHits, 1)
			return role, nil
		}
		// On error, invalidate the cache entry
		cs.invalidateRoleCache(roleID)
	}

	// If not cached, fetch from persistent storage
	atomic.AddInt64(&cs.stats.roleMisses, 1)
	role, err := cs.persistent.GetRole(roleID)
	if err != nil {
		return nil, err
	}

	// Cache the role and set its TTL
	cs.cache.CreateRole(role)
	cs.updateRoleTTL(role.ID)

	return role, nil
}

func (cs *CachedStorage) UpdateRole(role *Role) error {
	// First update in persistent storage
	err := cs.persistent.UpdateRole(role)
	if err != nil {
		return err
	}

	// Then update the cache
	cs.cache.UpdateRole(role)
	cs.updateRoleTTL(role.ID)

	return nil
}

func (cs *CachedStorage) DeleteRole(roleID string) error {
	// First delete from persistent storage
	err := cs.persistent.DeleteRole(roleID)
	if err != nil {
		return err
	}

	// Then invalidate the cache
	cs.invalidateRoleCache(roleID)

	// Since a role was deleted, all user-role caches should be invalidated
	cs.userRoleTTLs.Range(func(key, _ any) bool {
		userID := key.(string)
		cs.invalidateUserRoleCache(userID)
		return true
	})

	return nil
}

func (cs *CachedStorage) ListRoles() ([]*Role, error) {
	// Always fetch the full list from persistent storage
	// This operation is typically less frequent and needs to be complete
	return cs.persistent.ListRoles()
}

func (cs *CachedStorage) AddUserRole(userID, roleID string) error {
	// First add the user-role relationship in persistent storage
	err := cs.persistent.AddUserRole(userID, roleID)
	if err != nil {
		return err
	}

	// Invalidate user role cache - we'll rebuild it on next access
	cs.invalidateUserRoleCache(userID)

	return nil
}

func (cs *CachedStorage) RemoveUserRole(userID, roleID string) error {
	err := cs.persistent.RemoveUserRole(userID, roleID)
	if err != nil {
		return err
	}

	// Invalidate user role cache
	cs.invalidateUserRoleCache(userID)

	return nil
}

func (cs *CachedStorage) GetUserRoles(userID string) ([]string, error) {
	if cs.isUserRoleCached(userID) {
		roles, err := cs.cache.GetUserRoles(userID)
		if err == nil {
			atomic.AddInt64(&cs.stats.userRoleHits, 1)
			return roles, nil
		}
		// On error, invalidate the cache entry
		cs.invalidateUserRoleCache(userID)
	}

	// If not cached, fetch from persistent storage
	atomic.AddInt64(&cs.stats.userRoleMisses, 1)
	roles, err := cs.persistent.GetUserRoles(userID)
	if err != nil {
		return nil, err
	}

	// Update cache
	for _, roleID := range roles {
		cs.cache.AddUserRole(userID, roleID)
	}
	cs.updateUserRoleTTL(userID)

	return roles, nil
}

func (cs *CachedStorage) AddRolePermission(roleID, resource, action string) error {
	err := cs.persistent.AddRolePermission(roleID, resource, action)
	if err != nil {
		return err
	}

	// Invalidate role cache since permissions changed
	cs.invalidateRoleCache(roleID)

	return nil
}

func (cs *CachedStorage) RemoveRolePermission(roleID, resource string) error {
	err := cs.persistent.RemoveRolePermission(roleID, resource)
	if err != nil {
		return err
	}

	// Invalidate role cache since permissions changed
	cs.invalidateRoleCache(roleID)

	return nil
}

func (cs *CachedStorage) HasPermission(roleID, resource, action string) (bool, error) {
	if cs.isRoleCached(roleID) {
		return cs.cache.HasPermission(roleID, resource, action)
	}

	hasPermission, err := cs.persistent.HasPermission(roleID, resource, action)
	if err != nil {
		return false, err
	}

	// If has permission, asynchronously cache the role details
	// to speed up subsequent checks, without blocking the current request.
	if hasPermission {
		go func(roleID string) {
			role, err := cs.persistent.GetRole(roleID)
			if err == nil {
				cs.cache.CreateRole(role)
				cs.updateRoleTTL(roleID)
			}
		}(roleID)
	}

	return hasPermission, nil
}

func (cs *CachedStorage) Close() error {
	// Stop the cleanup goroutine
	close(cs.stopCleanup)

	// Close the underlying persistent storage
	return cs.persistent.Close()
}

// Stats returns cache performance statistics.
// Returns:
//
//	roleHits: number of times roles were found in cache
//	roleMisses: number of times roles had to be fetched from storage
//	userRoleHits: number of times user roles were found in cache
//	userRoleMisses: number of times user roles had to be fetched from storage
func (cs *CachedStorage) Stats() (roleHits, roleMisses, userRoleHits, userRoleMisses int64) {
	return atomic.LoadInt64(&cs.stats.roleHits),
		atomic.LoadInt64(&cs.stats.roleMisses),
		atomic.LoadInt64(&cs.stats.userRoleHits),
		atomic.LoadInt64(&cs.stats.userRoleMisses)
}

func (cs *CachedStorage) ClearCache() {
	cs.countMutex.Lock()
	defer cs.countMutex.Unlock()

	// Create new cache storage
	cs.cache = NewMemoryStorage()

	// Reset TTL maps
	cs.roleTTLs = sync.Map{}
	cs.userRoleTTLs = sync.Map{}

	// Reset cache counters
	cs.roleCacheCount = 0
	cs.userRoleCacheCount = 0

	// Reset statistics
	atomic.StoreInt64(&cs.stats.roleHits, 0)
	atomic.StoreInt64(&cs.stats.roleMisses, 0)
	atomic.StoreInt64(&cs.stats.userRoleHits, 0)
	atomic.StoreInt64(&cs.stats.userRoleMisses, 0)
}

// GetCacheSize returns the current size of the role and user-role caches.
func (cs *CachedStorage) GetCacheSize() (int, int) {
	cs.countMutex.RLock()
	defer cs.countMutex.RUnlock()
	return cs.roleCacheCount, cs.userRoleCacheCount
}
