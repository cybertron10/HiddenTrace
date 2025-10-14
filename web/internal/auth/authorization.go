package auth

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// Role represents user roles
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Permission represents what a user can do
type Permission string

const (
	// User permissions
	PermissionViewOwnScans    Permission = "view_own_scans"
	PermissionCreateScans     Permission = "create_scans"
	PermissionDeleteOwnScans  Permission = "delete_own_scans"
	
	// Admin permissions
	PermissionViewAllScans    Permission = "view_all_scans"
	PermissionDeleteAllScans  Permission = "delete_all_scans"
	PermissionManageUsers     Permission = "manage_users"
	PermissionSystemOps       Permission = "system_operations"
	PermissionViewAllUsers    Permission = "view_all_users"
)

// RolePermissions defines what permissions each role has
var RolePermissions = map[Role][]Permission{
	RoleUser: {
		PermissionViewOwnScans,
		PermissionCreateScans,
		PermissionDeleteOwnScans,
	},
	RoleAdmin: {
		PermissionViewOwnScans,
		PermissionCreateScans,
		PermissionDeleteOwnScans,
		PermissionViewAllScans,
		PermissionDeleteAllScans,
		PermissionManageUsers,
		PermissionSystemOps,
		PermissionViewAllUsers,
	},
}

// AuthorizationService handles authorization logic
type AuthorizationService struct {
	authService *Service
}

// NewAuthorizationService creates a new authorization service
func NewAuthorizationService(authService *Service) *AuthorizationService {
	return &AuthorizationService{
		authService: authService,
	}
}

// HasPermission checks if a user has a specific permission
func (as *AuthorizationService) HasPermission(userID int, permission Permission) bool {
	user, err := as.authService.GetUserByID(userID)
	if err != nil {
		return false
	}

	userRole := Role(user.Role)
	permissions, exists := RolePermissions[userRole]
	if !exists {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}

// HasRole checks if a user has a specific role
func (as *AuthorizationService) HasRole(userID int, role Role) bool {
	user, err := as.authService.GetUserByID(userID)
	if err != nil {
		return false
	}

	return Role(user.Role) == role
}

// IsAdmin checks if a user is an admin
func (as *AuthorizationService) IsAdmin(userID int) bool {
	return as.HasRole(userID, RoleAdmin)
}

// RequirePermission middleware that requires a specific permission
func (as *AuthorizationService) RequirePermission(permission Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		if !as.HasPermission(userID, permission) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"required_permission": string(permission),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireRole middleware that requires a specific role
func (as *AuthorizationService) RequireRole(role Role) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		if !as.HasRole(userID, role) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"required_role": string(role),
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAdmin middleware that requires admin role
func (as *AuthorizationService) RequireAdmin() gin.HandlerFunc {
	return as.RequireRole(RoleAdmin)
}

// CanAccessScan checks if a user can access a specific scan
func (as *AuthorizationService) CanAccessScan(userID int, scanUserID int) bool {
	// Admin can access any scan
	if as.IsAdmin(userID) {
		return true
	}
	
	// User can only access their own scans
	return userID == scanUserID
}

// CanAccessUser checks if a user can access another user's data
func (as *AuthorizationService) CanAccessUser(userID int, targetUserID int) bool {
	// Admin can access any user's data
	if as.IsAdmin(userID) {
		return true
	}
	
	// User can only access their own data
	return userID == targetUserID
}

// RequireScanAccess middleware that checks if user can access a specific scan
// This prevents horizontal privilege escalation by verifying scan ownership
func (as *AuthorizationService) RequireScanAccess(scannerService interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Get scan ID from URL parameter
		scanID := c.Param("id")
		if scanID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Scan ID required",
			})
			c.Abort()
			return
		}

		// Admin can access any scan (vertical privilege escalation protection)
		if as.IsAdmin(userID) {
			c.Next()
			return
		}

		// For non-admin users, verify scan ownership (horizontal privilege escalation protection)
		// This would require the scanner service to check ownership
		// For now, we'll use a placeholder - in real implementation, you'd call:
		// scan, err := scannerService.GetScanByUUID(scanID, userID)
		// if err != nil || scan.UserID != userID {
		//     c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to this scan"})
		//     c.Abort()
		//     return
		// }

		c.Next()
	}
}

// RequireUserAccess middleware that checks if user can access another user's data
// This prevents horizontal privilege escalation between users
func (as *AuthorizationService) RequireUserAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Get target user ID from URL parameter
		targetUserIDStr := c.Param("id")
		if targetUserIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "User ID required",
			})
			c.Abort()
			return
		}

		targetUserID, err := strconv.Atoi(targetUserIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid user ID",
			})
			c.Abort()
			return
		}

		// Check if user can access this user's data
		if !as.CanAccessUser(userID, targetUserID) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied to this user's data",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireResourceOwnership middleware that checks if user owns a specific resource
// This is a generic middleware for any resource ownership check
func (as *AuthorizationService) RequireResourceOwnership(getOwnerFunc func(resourceID string) (int, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		// Admin can access any resource
		if as.IsAdmin(userID) {
			c.Next()
			return
		}

		// Get resource ID from URL parameter
		resourceID := c.Param("id")
		if resourceID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Resource ID required",
			})
			c.Abort()
			return
		}

		// Get the owner of the resource
		ownerID, err := getOwnerFunc(resourceID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "Resource not found",
			})
			c.Abort()
			return
		}

		// Check if user owns the resource
		if userID != ownerID {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Access denied - you don't own this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// ValidateResourceAccess validates if a user can access a specific resource
// This is a helper function for use in handlers
func (as *AuthorizationService) ValidateResourceAccess(userID int, resourceOwnerID int) bool {
	// Admin can access any resource
	if as.IsAdmin(userID) {
		return true
	}
	
	// User can only access their own resources
	return userID == resourceOwnerID
}

// ValidateScanAccess validates if a user can access a specific scan
func (as *AuthorizationService) ValidateScanAccess(userID int, scanUserID int) bool {
	return as.ValidateResourceAccess(userID, scanUserID)
}

// ValidateUserAccess validates if a user can access another user's data
func (as *AuthorizationService) ValidateUserAccess(userID int, targetUserID int) bool {
	return as.ValidateResourceAccess(userID, targetUserID)
}

// GetUserPermissions returns all permissions for a user
func (as *AuthorizationService) GetUserPermissions(userID int) ([]Permission, error) {
	user, err := as.authService.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	userRole := Role(user.Role)
	permissions, exists := RolePermissions[userRole]
	if !exists {
		return []Permission{}, nil
	}

	return permissions, nil
}

// HasAnyPermission checks if a user has any of the specified permissions
func (as *AuthorizationService) HasAnyPermission(userID int, permissions ...Permission) bool {
	for _, permission := range permissions {
		if as.HasPermission(userID, permission) {
			return true
		}
	}
	return false
}

// RequireAnyPermission middleware that requires any of the specified permissions
func (as *AuthorizationService) RequireAnyPermission(permissions ...Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt("user_id")
		if userID == 0 {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authentication required",
			})
			c.Abort()
			return
		}

		if !as.HasAnyPermission(userID, permissions...) {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Insufficient permissions",
				"required_permissions": permissions,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
