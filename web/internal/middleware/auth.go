package middleware

import (
	"net/http"
	"strings"

	"vidusec/web/internal/auth"

	"github.com/gin-gonic/gin"
)

// AuthRequired middleware checks for valid JWT token
func AuthRequired(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check if header starts with "Bearer "
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		// Validate token
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)

		c.Next()
	}
}

// WebAuthRequired middleware for HTML pages - checks cookies and redirects to login
func WebAuthRequired(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First try to get token from Authorization header (for API calls)
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString != authHeader {
				claims, err := authService.ValidateToken(tokenString)
				if err == nil {
					c.Set("user_id", claims.UserID)
					c.Set("username", claims.Username)
					c.Next()
					return
				}
			}
		}

		// Try to get token from cookie
		tokenCookie, err := c.Cookie("auth_token")
		if err != nil || tokenCookie == "" {
			// No valid token found, redirect to login
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		// Validate token from cookie
		claims, err := authService.ValidateToken(tokenCookie)
		if err != nil {
			// Invalid token, redirect to login
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)

		c.Next()
	}
}

// OptionalAuth middleware checks for JWT token but doesn't require it
func OptionalAuth(authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString != authHeader {
				claims, err := authService.ValidateToken(tokenString)
				if err == nil {
					c.Set("user_id", claims.UserID)
					c.Set("username", claims.Username)
				}
			}
		}
		c.Next()
	}
}
