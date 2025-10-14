# Authorization System - Privilege Escalation Protection

This document explains how the centralized authorization system protects against both **vertical** and **horizontal** privilege escalation attacks.

## Types of Privilege Escalation

### 1. Vertical Privilege Escalation
**Definition**: A user gains access to functions or data that their role doesn't allow.

**Example**: A regular user trying to access admin functions.

**Protection**: Role-based permissions and middleware.

### 2. Horizontal Privilege Escalation  
**Definition**: A user gains access to another user's data at the same privilege level.

**Example**: User A trying to access User B's scan results.

**Protection**: Resource ownership validation and access control.

## How the System Protects Against Both

### Vertical Privilege Escalation Protection

```go
// 1. Role-based middleware
admin.Use(authzService.RequireAdmin())

// 2. Permission-based middleware
admin.GET("/users", 
    authzService.RequirePermission(PermissionViewAllUsers), 
    handler)

// 3. Multiple permission requirements
admin.DELETE("/users/:id", 
    authzService.RequirePermission(PermissionManageUsers), 
    handler)
```

### Horizontal Privilege Escalation Protection

```go
// 1. Resource ownership middleware
scanner.GET("/scans/:id", 
    authzService.RequireResourceOwnership(getScanOwner), 
    handler)

// 2. User access validation
admin.GET("/users/:id/stats", 
    authzService.RequireUserAccess(), 
    handler)

// 3. In-handler validation
func (h *Handler) GetScan(c *gin.Context) {
    userID := c.GetInt("user_id")
    scanID := c.Param("id")
    
    // Get scan and validate ownership
    scan, err := h.scannerService.GetScanByUUID(scanID, userID)
    if err != nil {
        c.JSON(404, gin.H{"error": "Scan not found"})
        return
    }
    
    // Additional validation (redundant but safe)
    if !h.authzService.ValidateScanAccess(userID, scan.UserID) {
        c.JSON(403, gin.H{"error": "Access denied"})
        return
    }
    
    // Return scan data
    c.JSON(200, scan)
}
```

## Complete Protection Examples

### Example 1: Scan Access Endpoint

```go
// Route definition with protection
scanner.GET("/scans/:id", 
    middleware.AuthRequired(authService),           // Authentication
    authzService.RequireResourceOwnership(getScanOwner), // Ownership validation
    apiHandler.GetScan)

// Handler implementation
func (h *Handler) GetScan(c *gin.Context) {
    userID := c.GetInt("user_id")
    scanID := c.Param("id")
    
    // Get scan (already validated by middleware)
    scan, err := h.scannerService.GetScanByUUID(scanID, userID)
    if err != nil {
        c.JSON(404, gin.H{"error": "Scan not found"})
        return
    }
    
    c.JSON(200, scan)
}

// Helper function for middleware
func getScanOwner(scanID string) (int, error) {
    // Implementation would fetch scan owner from database
    // This is called by RequireResourceOwnership middleware
}
```

### Example 2: User Management Endpoint

```go
// Route definition with multiple protections
admin.GET("/users/:id/stats", 
    authzService.RequireAdmin(),                    // Vertical protection
    authzService.RequirePermission(PermissionViewAllUsers), // Permission check
    authzService.RequireUserAccess(),               // Horizontal protection
    apiHandler.GetUserStats)

// Handler implementation
func (h *Handler) GetUserStats(c *gin.Context) {
    userID := c.GetInt("user_id")
    targetUserIDStr := c.Param("id")
    targetUserID, _ := strconv.Atoi(targetUserIDStr)
    
    // Additional validation (redundant but safe)
    if !h.authzService.ValidateUserAccess(userID, targetUserID) {
        c.JSON(403, gin.H{"error": "Access denied"})
        return
    }
    
    // Get user stats
    stats, err := h.scannerService.GetUserStats(targetUserID)
    if err != nil {
        c.JSON(500, gin.H{"error": "Failed to get stats"})
        return
    }
    
    c.JSON(200, stats)
}
```

### Example 3: Flexible Permission Requirements

```go
// Require any of multiple permissions
admin.POST("/bulk-operation", 
    authzService.RequireAnyPermission(
        PermissionSystemOps,
        PermissionManageUsers,
    ), 
    handler)

// Require specific permission
admin.DELETE("/users/:id", 
    authzService.RequirePermission(PermissionManageUsers), 
    handler)
```

## Best Practices

### 1. Defense in Depth
```go
// Multiple layers of protection
router.GET("/sensitive/:id", 
    middleware.AuthRequired(authService),           // Layer 1: Authentication
    authzService.RequirePermission(permission),     // Layer 2: Permission
    authzService.RequireResourceOwnership(getOwner), // Layer 3: Ownership
    handler)                                        // Layer 4: Handler validation
```

### 2. Consistent Validation
```go
// Always validate in handlers too (redundant but safe)
func (h *Handler) SomeEndpoint(c *gin.Context) {
    userID := c.GetInt("user_id")
    resourceID := c.Param("id")
    
    // Get resource
    resource, err := h.service.GetResource(resourceID)
    if err != nil {
        c.JSON(404, gin.H{"error": "Not found"})
        return
    }
    
    // Validate access (even though middleware already did)
    if !h.authzService.ValidateResourceAccess(userID, resource.OwnerID) {
        c.JSON(403, gin.H{"error": "Access denied"})
        return
    }
    
    // Process request
    c.JSON(200, resource)
}
```

### 3. Clear Error Messages
```go
// Don't reveal too much information
c.JSON(403, gin.H{
    "error": "Access denied",
    // Don't include: "required_permission": "admin_only"
})
```

## Testing Authorization

### Unit Tests
```go
func TestAuthorization(t *testing.T) {
    authz := auth.NewAuthorizationService(authService)
    
    // Test vertical escalation protection
    assert.False(t, authz.IsAdmin(2)) // Regular user
    assert.True(t, authz.IsAdmin(1))  // Admin user
    
    // Test horizontal escalation protection
    assert.False(t, authz.ValidateResourceAccess(2, 3)) // User 2 accessing User 3's resource
    assert.True(t, authz.ValidateResourceAccess(2, 2))  // User 2 accessing own resource
    assert.True(t, authz.ValidateResourceAccess(1, 2))  // Admin accessing any resource
}
```

### Integration Tests
```go
func TestScanAccess(t *testing.T) {
    // Test that user cannot access another user's scan
    req := httptest.NewRequest("GET", "/scans/other-user-scan-id", nil)
    req.Header.Set("Authorization", "Bearer user-token")
    
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)
    
    assert.Equal(t, 403, w.Code)
    assert.Contains(t, w.Body.String(), "Access denied")
}
```

## Summary

The centralized authorization system provides comprehensive protection against both types of privilege escalation:

✅ **Vertical Privilege Escalation**: Prevented by role-based permissions and admin middleware
✅ **Horizontal Privilege Escalation**: Prevented by resource ownership validation and access control
✅ **Defense in Depth**: Multiple layers of protection
✅ **Centralized Control**: Single source of truth for authorization logic
✅ **Easy Maintenance**: Add new permissions without touching individual handlers
✅ **Comprehensive Testing**: Easy to unit test and integration test

This system ensures that users can only access the resources and perform the actions that their role and permissions allow, preventing both types of privilege escalation attacks.
