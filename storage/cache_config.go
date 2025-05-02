package storage

import "time"

type CacheConfig struct {
	EnableRoleCache      bool          // Enable caching for roles
	RoleCacheTTL         time.Duration // Time to live for cached roles
	EnableUserRoleCache  bool          // Enable caching for user-role relationships
	UserRoleCacheTTL     time.Duration // Time to live for cached user-role relationships
	CleanupInterval      time.Duration // Interval for cache cleanup
	MaxRoleCacheSize     int           // Maximum size of the role cache, 0 means no limit
	MaxUserRoleCacheSize int           // Maximum size of the user-role cache, 0 means no limit
}

func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		EnableRoleCache:      true,
		RoleCacheTTL:         30 * time.Minute,
		EnableUserRoleCache:  true,
		UserRoleCacheTTL:     15 * time.Minute,
		CleanupInterval:      5 * time.Minute,
		MaxRoleCacheSize:     1000,
		MaxUserRoleCacheSize: 5000,
	}
}
