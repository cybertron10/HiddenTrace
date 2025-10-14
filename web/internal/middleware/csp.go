package middleware

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/gin-gonic/gin"
)

// CSPMiddleware provides Content Security Policy with nonce support
func CSPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Generate a unique nonce for this request
		nonce := generateNonce()
		c.Set("csp_nonce", nonce)

		// Content Security Policy (HTTP development-friendly)
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
			"img-src 'self' data: blob: https:; " +
			"font-src 'self' https://cdnjs.cloudflare.com https://cdn.tailwindcss.com; " +
			"connect-src 'self' http://localhost:* http://127.0.0.1:* http://16.170.226.104:*; " +
			"frame-src 'self'; " +
			"object-src 'none'"

		c.Header("Content-Security-Policy", csp)
		c.Next()
	}
}

// SecurityHeadersMiddleware sets additional security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Next()
	}
}

// generateNonce creates a cryptographically secure random nonce
func generateNonce() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

// GetNonce retrieves the CSP nonce from the context
func GetNonce(c *gin.Context) string {
	if nonce, exists := c.Get("csp_nonce"); exists {
		return nonce.(string)
	}
	return ""
}
