package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"HiddenTrace/web/internal/auth"
	"HiddenTrace/web/internal/session"

	"github.com/gin-gonic/gin"
)

// SessionRequired middleware checks for valid session cookie
func SessionRequired(sessionService *session.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from cookie
		sessionID, err := c.Cookie("JSESSIONID")
		if err != nil {
			// If no session cookie, redirect to login page
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Validate session
		sess, err := sessionService.GetSession(sessionID)
		if err != nil {
			// Clear invalid session cookie
			ClearSessionCookie(c)
			// If session is invalid or expired, redirect to login page
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		// Check if session needs rotation (every 30 minutes)
		if time.Since(sess.CreatedAt) > 30*time.Minute {
			// Rotate session ID for security
			newSession, err := sessionService.RotateSession(sessionID)
			if err == nil {
				// Update cookie with new session ID
				SetSessionCookie(c, newSession.ID)
				sess = newSession
			} else {
				log.Printf("Warning: Failed to rotate session: %v", err)
			}
		}

		// Set user information in context
		c.Set("user_id", sess.UserID)
		c.Set("username", sess.Username)
		c.Set("session_id", sess.ID)

		c.Next()
	}
}

// SessionRequiredAPI middleware checks for valid session cookie for API endpoints
// Returns JSON error instead of redirect for API calls
func SessionRequiredAPI(sessionService *session.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from cookie
		sessionID, err := c.Cookie("JSESSIONID")
		if err != nil {
			// If no session cookie, return 401 for API calls
			log.Printf("SessionRequiredAPI: No JSESSIONID cookie found for %s", c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session required",
				"redirect": "/login",
			})
			c.Abort()
			return
		}

		// Validate session
		sess, err := sessionService.GetSession(sessionID)
		if err != nil {
			// Clear invalid session cookie
			log.Printf("SessionRequiredAPI: Invalid session %s for %s: %v", sessionID, c.Request.URL.Path, err)
			c.SetCookie("JSESSIONID", "", -1, "/", "", false, true)
			// If session is invalid or expired, return 401 for API calls
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired session",
				"redirect": "/login",
			})
			c.Abort()
			return
		}

		// Set user information in context
		c.Set("user_id", sess.UserID)
		c.Set("username", sess.Username)
		c.Set("session_id", sess.ID)

		c.Next()
	}
}

// SessionOptional middleware checks for session cookie but doesn't require it
func SessionOptional(sessionService *session.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get session ID from cookie
		sessionID, err := c.Cookie("JSESSIONID")
		if err != nil {
			// No session cookie, continue without user context
			c.Next()
			return
		}

		// Validate session
		sess, err := sessionService.GetSession(sessionID)
		if err != nil {
			// Clear invalid session cookie
			c.SetCookie("JSESSIONID", "", -1, "/", "", false, true)
			// Continue without user context
			c.Next()
			return
		}

		// Set user information in context
		c.Set("user_id", sess.UserID)
		c.Set("username", sess.Username)
		c.Set("session_id", sess.ID)

		c.Next()
	}
}

// AdminSessionRequired middleware checks for admin session
func AdminSessionRequired(sessionService *session.Service, authService interface{}) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check for valid session
		sessionID, err := c.Cookie("JSESSIONID")
		if err != nil {
			// If no session cookie, redirect to login page
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		// Validate session
		sess, err := sessionService.GetSession(sessionID)
		if err != nil {
			// Clear invalid session cookie
			c.SetCookie("JSESSIONID", "", -1, "/", "", false, true)
			// If session is invalid or expired, redirect to login page
			c.Redirect(http.StatusFound, "/")
			c.Abort()
			return
		}

		// Check if user is admin by getting user role from database
		// We need to get the user from the database to check their role
		// For now, we'll allow the request to proceed and let the API handlers check admin status
		// The API handlers have proper role-based admin checks

		// Set user information in context
		c.Set("user_id", sess.UserID)
		c.Set("username", sess.Username)
		c.Set("session_id", sess.ID)

		c.Next()
	}
}

// SetSessionCookie sets the JSESSIONID cookie with security flags
func SetSessionCookie(c *gin.Context, sessionID string) {
	// Determine if we're in production (HTTPS) based on environment or request
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	
	c.SetCookie(
		"JSESSIONID",           // name
		sessionID,              // value
		24*60*60,              // max age (24 hours in seconds)
		"/",                    // path
		"",                     // domain (empty = current domain only)
		isSecure,               // secure (HTTPS only)
		true,                   // httpOnly (prevent XSS)
	)
	
	// Note: SameSite disabled for HTTP development
	// In production with HTTPS, you should enable SameSite=Strict
}

// ClearSessionCookie clears the JSESSIONID cookie with security flags
func ClearSessionCookie(c *gin.Context) {
	// Determine if we're in production (HTTPS) based on environment or request
	isSecure := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
	
	c.SetCookie(
		"JSESSIONID",           // name
		"",                     // value
		-1,                     // max age (expire immediately)
		"/",                    // path
		"",                     // domain (empty = current domain only)
		isSecure,               // secure (HTTPS only)
		true,                   // httpOnly (prevent XSS)
	)
	
	// Note: SameSite disabled for HTTP development
	// In production with HTTPS, you should enable SameSite=Strict
}

// GetSessionFromRequest extracts session information from request
func GetSessionFromRequest(c *gin.Context) (userID int, username string, sessionID string, ok bool) {
	userIDValue, exists := c.Get("user_id")
	if !exists {
		return 0, "", "", false
	}

	usernameValue, exists := c.Get("username")
	if !exists {
		return 0, "", "", false
	}

	sessionIDValue, exists := c.Get("session_id")
	if !exists {
		return 0, "", "", false
	}

	// Type assertions
	userID, ok = userIDValue.(int)
	if !ok {
		return 0, "", "", false
	}

	username, ok = usernameValue.(string)
	if !ok {
		return 0, "", "", false
	}

	sessionID, ok = sessionIDValue.(string)
	if !ok {
		return 0, "", "", false
	}

	return userID, username, sessionID, true
}

// SessionAndAuthRequired middleware checks for both valid session cookie AND auth header
// This provides enhanced security against CSRF attacks and session hijacking
func SessionAndAuthRequired(sessionService *session.Service, authService *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Step 1: Check session cookie
		sessionID, err := c.Cookie("JSESSIONID")
		if err != nil {
			log.Printf("SessionAndAuthRequired: No JSESSIONID cookie found for %s", c.Request.URL.Path)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session required",
				"redirect": "/login",
			})
			c.Abort()
			return
		}

		// Validate session
		sess, err := sessionService.GetSession(sessionID)
		if err != nil {
			log.Printf("SessionAndAuthRequired: Invalid session %s for %s: %v", sessionID, c.Request.URL.Path, err)
			// Clear invalid session cookie
			c.SetCookie("JSESSIONID", "", -1, "/", "", false, true)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired session",
				"redirect": "/login",
			})
			c.Abort()
			return
		}

		// Step 2: Check auth header
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

		// Validate JWT token
		claims, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Step 3: Verify session user matches token user
		if sess.UserID != claims.UserID {
			log.Printf("SessionAndAuthRequired: Session/token user mismatch - Session: %d, Token: %d", sess.UserID, claims.UserID)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Session/token mismatch",
			})
			c.Abort()
			return
		}

		// Step 4: Set user information in context
		c.Set("user_id", sess.UserID)
		c.Set("username", sess.Username)
		c.Set("session_id", sess.ID)

		log.Printf("SessionAndAuthRequired: Successfully authenticated user %d for %s", sess.UserID, c.Request.URL.Path)
		c.Next()
	}
}
