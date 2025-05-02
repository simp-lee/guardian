package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// SQLStorage implements Storage interface using a SQL database.
type SQLStorage struct {
	db *sql.DB
}

// NewSQLStorage creates a new SQL-based storage instance.
func NewSQLStorage(db *sql.DB) (Storage, error) {
	if db == nil {
		return nil, errors.New("storage: db cannot be nil")
	}

	storage := &SQLStorage{
		db: db,
	}

	if err := storage.initTables(); err != nil {
		return nil, err
	}

	return storage, nil
}

// initTables creates the necessary tables if they don't exist.
func (s *SQLStorage) initTables() error {
	// Create roles table if it doesn't exist
	_, err := s.db.Exec(`
        CREATE TABLE IF NOT EXISTS guardian_roles (
            id VARCHAR(255) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            permissions TEXT,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create roles table: %w", err)
	}

	// Create user_roles table if it doesn't exist
	_, err = s.db.Exec(`
        CREATE TABLE IF NOT EXISTS guardian_user_roles (
            user_id VARCHAR(255) NOT NULL,
            role_id VARCHAR(255) NOT NULL,
            created_at TIMESTAMP NOT NULL,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (role_id) REFERENCES guardian_roles(id) ON DELETE CASCADE
        )
    `)
	if err != nil {
		return fmt.Errorf("failed to create user_roles table: %w", err)
	}

	return nil
}

// CreateRole implements Storage.CreateRole.
func (s *SQLStorage) CreateRole(role *Role) error {
	if role.Permissions == nil {
		role.Permissions = make(map[string][]string)
	}

	// Serialize permissions to JSON
	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to serialize permissions: %w", err)
	}

	// Check if the role already exists
	var exists bool
	err = s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM guardian_roles WHERE id = ?)", role.ID).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check role existence: %w", err)
	}
	if exists {
		return ErrRoleAlreadyExists
	}

	// Insert the role into the database
	_, err = s.db.Exec(
		"INSERT INTO guardian_roles (id, name, description, permissions, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		role.ID, role.Name, role.Description, permissionsJSON, role.CreatedAt, role.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}

	return nil
}

// GetRole implements Storage.GetRole.
func (s *SQLStorage) GetRole(roleID string) (*Role, error) {
	if roleID == "" {
		return nil, errors.New("storage: roleID cannot be empty")
	}

	var role Role
	var permissionsJSON []byte

	err := s.db.QueryRow(
		"SELECT id, name, description, permissions, created_at, updated_at FROM guardian_roles WHERE id = ?",
		roleID,
	).Scan(&role.ID, &role.Name, &role.Description, &permissionsJSON, &role.CreatedAt, &role.UpdatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Deserialize permissions
	role.Permissions = make(map[string][]string)
	if len(permissionsJSON) > 0 {
		if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
			return nil, fmt.Errorf("failed to deserialize permissions: %w", err)
		}
	}

	return &role, nil
}

// UpdateRole implements Storage.UpdateRole.
func (s *SQLStorage) UpdateRole(role *Role) error {
	// Serialize permissions to JSON
	permissionsJSON, err := json.Marshal(role.Permissions)
	if err != nil {
		return fmt.Errorf("failed to serialize permissions: %w", err)
	}

	// Update the role
	result, err := s.db.Exec(
		"UPDATE guardian_roles SET name = ?, description = ?, permissions = ?, updated_at = ? WHERE id = ?",
		role.Name, role.Description, permissionsJSON, time.Now(), role.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrRoleNotFound
	}

	return nil
}

// DeleteRole implements Storage.DeleteRole.
func (s *SQLStorage) DeleteRole(roleID string) error {
	// Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete role
	result, err := tx.Exec("DELETE FROM guardian_roles WHERE id = ?", roleID)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrRoleNotFound
	}

	// Note: user_roles should be automatically deleted via ON DELETE CASCADE

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// ListRoles implements Storage.ListRoles.
func (s *SQLStorage) ListRoles() ([]*Role, error) {
	rows, err := s.db.Query("SELECT id, name, description, permissions, created_at, updated_at FROM guardian_roles")
	if err != nil {
		return nil, fmt.Errorf("failed to query roles: %w", err)
	}
	defer rows.Close()

	var roles []*Role
	for rows.Next() {
		var role Role
		var permissionsJSON []byte
		err := rows.Scan(&role.ID, &role.Name, &role.Description, &permissionsJSON, &role.CreatedAt, &role.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Deserialize permissions
		role.Permissions = make(map[string][]string)
		if len(permissionsJSON) > 0 {
			if err := json.Unmarshal(permissionsJSON, &role.Permissions); err != nil {
				return nil, fmt.Errorf("failed to deserialize permissions: %w", err)
			}
		}

		roles = append(roles, &role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// AddUserRole implements Storage.AddUserRole.
func (s *SQLStorage) AddUserRole(userID, roleID string) error {
	// Check if role exists using EXISTS subquery
	var roleExists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM guardian_roles WHERE id = ?)", roleID).Scan(&roleExists)
	if err != nil {
		return fmt.Errorf("failed to check if role exists: %w", err)
	}
	if !roleExists {
		return ErrRoleNotFound
	}

	// Check if user already has the role using EXISTS subquery
	var userHasRole bool
	err = s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM guardian_user_roles WHERE user_id = ? AND role_id = ?)",
		userID, roleID).Scan(&userHasRole)
	if err != nil {
		return fmt.Errorf("failed to check if user has role: %w", err)
	}
	if userHasRole {
		return ErrUserAlreadyHasRole
	}

	// Add user role
	_, err = s.db.Exec(
		"INSERT INTO guardian_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)",
		userID, roleID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to add user role: %w", err)
	}

	return nil
}

// RemoveUserRole implements Storage.RemoveUserRole.
func (s *SQLStorage) RemoveUserRole(userID, roleID string) error {
	result, err := s.db.Exec("DELETE FROM guardian_user_roles WHERE user_id = ? AND role_id = ?",
		userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove user role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return ErrUserDoesNotHaveRole
	}

	return nil
}

// GetUserRoles implements Storage.GetUserRoles.
func (s *SQLStorage) GetUserRoles(userID string) ([]string, error) {
	rows, err := s.db.Query("SELECT role_id FROM guardian_user_roles WHERE user_id = ?", userID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var roleID string
		if err := rows.Scan(&roleID); err != nil {
			return nil, fmt.Errorf("failed to scan role ID: %w", err)
		}
		roles = append(roles, roleID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user roles: %w", err)
	}

	return roles, nil
}

// AddRolePermission implements Storage.AddRolePermission.
func (s *SQLStorage) AddRolePermission(roleID, resource, action string) error {
	// Start transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current permissions
	var permissionsJSON []byte
	err = tx.QueryRow("SELECT permissions FROM guardian_roles WHERE id = ?", roleID).Scan(&permissionsJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("failed to get role permissions: %w", err)
	}

	// Deserialize permissions
	permissions := make(map[string][]string)
	if len(permissionsJSON) > 0 {
		if err := json.Unmarshal(permissionsJSON, &permissions); err != nil {
			return fmt.Errorf("failed to deserialize permissions: %w", err)
		}
	}

	// Check if resource exists, if not, create it
	actions := permissions[resource]

	// Check if permission already exists
	if !slices.Contains(actions, action) {
		// Only add if it doesn't exist
		permissions[resource] = append(actions, action)

		// Serialize updated permissions
		updatedJSON, err := json.Marshal(permissions)
		if err != nil {
			return fmt.Errorf("failed to serialize permissions: %w", err)
		}

		// Update the role with new permissions
		_, err = tx.Exec(
			"UPDATE guardian_roles SET permissions = ?, updated_at = ? WHERE id = ?",
			updatedJSON, time.Now(), roleID,
		)
		if err != nil {
			return fmt.Errorf("failed to update role permissions: %w", err)
		}
	}

	return tx.Commit()
}

// RemoveRolePermission implements Storage.RemoveRolePermission.
func (s *SQLStorage) RemoveRolePermission(roleID, resource string) error {
	// Start transaction
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get current permissions
	var permissionsJSON []byte
	err = tx.QueryRow("SELECT permissions FROM guardian_roles WHERE id = ?", roleID).Scan(&permissionsJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("failed to get role permissions: %w", err)
	}

	// Deserialize permissions
	permissions := make(map[string][]string)
	if len(permissionsJSON) > 0 {
		if err := json.Unmarshal(permissionsJSON, &permissions); err != nil {
			return fmt.Errorf("failed to deserialize permissions: %w", err)
		}
	}

	// Check if resource exists
	if _, exists := permissions[resource]; !exists {
		return ErrPermissionNotFound
	}

	// Remove resource
	delete(permissions, resource)

	// Serialize updated permissions
	updatedJSON, err := json.Marshal(permissions)
	if err != nil {
		return fmt.Errorf("failed to serialize updated permissions: %w", err)
	}

	// Update the role with new permissions
	_, err = tx.Exec(
		"UPDATE guardian_roles SET permissions = ?, updated_at = ? WHERE id = ?",
		updatedJSON, time.Now(), roleID,
	)
	if err != nil {
		return fmt.Errorf("failed to update role permissions: %w", err)
	}

	return tx.Commit()
}

// HasPermission implements Storage.HasPermission.
// This method only checks for exact permission matches - wildcard handling is done at the RBAC service level
func (s *SQLStorage) HasPermission(roleID, resource, action string) (bool, error) {
	var permissionsJSON []byte
	err := s.db.QueryRow("SELECT permissions FROM guardian_roles WHERE id = ?", roleID).Scan(&permissionsJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrRoleNotFound
		}
		return false, fmt.Errorf("failed to get role permissions: %w", err)
	}

	// Deserialize permissions
	permissions := make(map[string][]string)
	if len(permissionsJSON) > 0 {
		if err := json.Unmarshal(permissionsJSON, &permissions); err != nil {
			return false, fmt.Errorf("failed to deserialize permissions: %w", err)
		}
	}

	// Check exact permission match only - leave wildcard/hierarchical logic to RBAC service
	actions, exists := permissions[resource]
	if !exists {
		return false, nil
	}

	return slices.Contains(actions, action), nil
}

// Close closes the database connection.
func (s *SQLStorage) Close() error {
	return s.db.Close()
}

// Helper functions for creating different database connections

// CreateMySQLStorage creates a new MySQL storage instance.
func CreateMySQLStorage(dsn string) (Storage, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	db.SetMaxOpenConns(25)                 // Set max open connections to 25
	db.SetMaxIdleConns(25)                 // Set max idle connections to 25
	db.SetConnMaxLifetime(5 * time.Minute) // Set max connection lifetime to 5 minutes

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping MySQL: %w", err)
	}

	return NewSQLStorage(db)
}

// CreatePostgresStorage creates a new PostgreSQL storage instance.
func CreatePostgresStorage(dsn string) (Storage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL connection: %w", err)
	}

	db.SetMaxOpenConns(25)                 // Set max open connections to 25
	db.SetMaxIdleConns(25)                 // Set max idle connections to 25
	db.SetConnMaxLifetime(5 * time.Minute) // Set max connection lifetime to 5 minutes

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	return NewSQLStorage(db)
}

// CreateSQLiteStorage creates a new SQLite storage instance.
// It automatically tries the CGO SQLite driver first, then falls back to pure Go if necessary.
// Foreign key constraints are automatically enabled.
func CreateSQLiteStorage(filepath string) (Storage, error) {
	if filepath == "" {
		return nil, errors.New("storage: SQLite filepath cannot be empty")
	}

	var db *sql.DB
	var err error

	// CGO driver first: github.com/mattn/go-sqlite3
	// then pure Go driver: modernc.org/sqlite
	var driversToTry = []string{"sqlite3", "sqlite"}

	for _, driver := range driversToTry {
		db, err = sql.Open(driver, filepath)
		if err != nil {
			continue
		}

		if err = db.Ping(); err != nil {
			db.Close()
			continue
		}

		if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
			db.Close()
			continue
		}

		// Successfully opened and configured SQLite connection
		return NewSQLStorage(db)
	}

	// If we reach here, all drivers failed
	return nil, fmt.Errorf("failed to connect to SQLite database with any available driver: %w", err)
}
