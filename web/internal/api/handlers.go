package api

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"HiddenTrace/web/internal/auth"
	"HiddenTrace/web/internal/database"
	"HiddenTrace/web/internal/middleware"
	"HiddenTrace/web/internal/scanner"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	scannerService *scanner.Service
	authService    *auth.Service
	AuthzService   *auth.AuthorizationService
}

func NewHandler(scannerService *scanner.Service, authService *auth.Service) *Handler {
	return &Handler{
		scannerService: scannerService,
		authService:    authService,
		AuthzService:   auth.NewAuthorizationService(authService),
	}
}

// Input validation functions
func isValidURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func sanitizeString(input string) string {
	// Remove potentially dangerous characters
	input = strings.TrimSpace(input)
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")
	input = strings.ReplaceAll(input, "\"", "&quot;")
	input = strings.ReplaceAll(input, "'", "&#x27;")
	input = strings.ReplaceAll(input, "&", "&amp;")
	return input
}


// Helper function to check if user has permission (uses centralized authorization)
func (h *Handler) hasPermission(userID int, permission auth.Permission) bool {
	return h.AuthzService.HasPermission(userID, permission)
}

// Helper function to check if user can access a scan (uses centralized authorization)
func (h *Handler) canAccessScan(userID int, scanUserID int) bool {
	return h.AuthzService.CanAccessScan(userID, scanUserID)
}

func isValidScanID(idStr string) bool {
	matched, _ := regexp.MatchString(`^\d+$`, idStr)
	return matched
}

func isValidUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

func normalizeURL(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	
	// Normalize to scheme + host + path for path-based matching
	// This allows different paths on the same host to be treated as separate scans
	normalized := u.Scheme + "://" + u.Host + u.Path
	
	// Remove trailing slash to ensure consistency (except for root path)
	if strings.HasSuffix(normalized, "/") && normalized != u.Scheme + "://" + u.Host + "/" {
		normalized = normalized[:len(normalized)-1]
	}
	
	return normalized
}

// Register handles user registration
func (h *Handler) Register(c *gin.Context) {
	var req auth.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		if err == auth.ErrUserExists {
			c.JSON(http.StatusConflict, gin.H{
				"error": "User already exists",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create user",
			})
		}
		return
	}

	c.JSON(http.StatusCreated, response)
}

// Login handles user login
func (h *Handler) Login(c *gin.Context) {
	var req auth.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
		})
		return
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		if err == auth.ErrUserNotFound || err == auth.ErrInvalidPassword {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid credentials",
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Login failed",
			})
		}
		return
	}

	// Clear any old auth_token cookie (from JWT-based auth)
	c.SetCookie("auth_token", "", -1, "/", "", false, true) // Expire immediately
	
	// Set the session cookie for web authentication
	if response.SessionID != "" {
		middleware.SetSessionCookie(c, response.SessionID)
	}

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *Handler) Logout(c *gin.Context) {
	// Get session ID from cookie
	sessionID, err := c.Cookie("JSESSIONID")
	if err != nil {
		sessionID = ""
	}

	// Get JWT token from Authorization header
	authHeader := c.GetHeader("Authorization")
	tokenString := ""
	if authHeader != "" {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	}

	// Invalidate the session and blacklist the JWT token
	err = h.authService.Logout(sessionID, tokenString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}
	
	// Clear the session cookie
	middleware.ClearSessionCookie(c)
	
	// Clear any old auth_token cookie (from JWT-based auth)
	c.SetCookie("auth_token", "", -1, "/", "", false, true) // Expire immediately
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetProfile returns the current user's profile
func (h *Handler) GetProfile(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": user,
	})
}

// StartScan initiates a new security scan
func (h *Handler) StartScan(c *gin.Context) {
	userID := c.GetInt("user_id")

	var req scanner.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	// Validate and sanitize input
	if !isValidURL(req.TargetURL) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid target URL",
		})
		return
	}

	// Note: We now use exact URL matching instead of normalized URLs

	// Validate limits
	if req.MaxDepth < 1 || req.MaxDepth > 50 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Max depth must be between 1 and 50",
		})
		return
	}

	if req.MaxPages < 1 || req.MaxPages > 100000 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Max pages must be between 1 and 100000",
		})
		return
	}

	// Set defaults
	if req.MaxDepth == 0 {
		req.MaxDepth = 10
	}
	if req.MaxPages == 0 {
		req.MaxPages = 20000
	}

	// Check if there's an existing scan for the same exact URL
	log.Printf("Checking for existing scan - UserID: %d, URL: %s", userID, req.TargetURL)
	existingScan, err := h.scannerService.GetScanByHost(userID, req.TargetURL)
	if err == nil && existingScan != nil {
		// Overwrite existing scan instead of creating new one
		log.Printf("Found existing scan %d (UUID: %s) for URL %s, overwriting...", existingScan.ID, existingScan.ScanUUID, req.TargetURL)
		_, err := h.scannerService.RescanScanByUUID(existingScan.ScanUUID, userID, &req)
		if err != nil {
			log.Printf("Error overwriting existing scan: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to update existing scan",
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"scan_id": existingScan.ID,
			"status":  "overwritten",
			"message": "Existing scan updated successfully",
		})
		return
	} else if err != nil {
		log.Printf("Error checking for existing scan: %v", err)
	} else {
		log.Printf("No existing scan found for URL %s, creating new scan", req.TargetURL)
	}

	// Debug logging for headers
	log.Printf("DEBUG: Scan request headers: %v", req.Headers)
	
	// Create new scan if no existing scan found
	response, err := h.scannerService.StartScan(userID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start scan",
		})
		return
	}

	c.JSON(http.StatusCreated, response)
}

// GetScans retrieves scans for the current user
func (h *Handler) GetScans(c *gin.Context) {
	userID := c.GetInt("user_id")

	// Parse pagination parameters
	limit := 20
	offset := 0

	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	scans, err := h.scannerService.GetScans(userID, limit, offset)
	if err != nil {
		log.Printf("Error retrieving scans for user %d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve scans",
		})
		return
	}

	log.Printf("Retrieved %d scans for user %d: %v", len(scans), userID, scans)
	c.JSON(http.StatusOK, gin.H{
		"scans": scans,
		"pagination": gin.H{
			"limit":  limit,
			"offset": offset,
		},
	})
}

// GetScan retrieves a specific scan by UUID
func (h *Handler) GetScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware
	// Get scan (admin can view any scan, regular users only their own)
	var scan *database.Scan
	var err error
	if h.AuthzService.IsAdmin(userID) {
		// Admin can view any scan
		scan, err = h.scannerService.GetScanByUUIDForAdmin(scanUUID)
	} else {
		// Regular user can only view their own scans (already validated by middleware)
		scan, err = h.scannerService.GetScanByUUID(scanUUID, userID)
	}
	
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan": scan,
	})
}

// DeleteScan deletes a specific scan by UUID
func (h *Handler) DeleteScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	log.Printf("Delete scan request - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Resource ownership is already validated by middleware
	// Delete the scan
	err := h.scannerService.DeleteScanByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error deleting scan - UserID: %d, ScanUUID: %s, Error: %v", userID, scanUUID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete scan",
		})
		return
	}

	log.Printf("Successfully deleted scan - UserID: %d, ScanUUID: %s", userID, scanUUID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Scan deleted successfully",
	})
}

// GetScanStatus returns the status of a specific scan by UUID
func (h *Handler) GetScanStatus(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware
	// Get scan status (admin can view any scan, regular users only their own)
	var scan *database.Scan
	var err error
	if h.AuthzService.IsAdmin(userID) {
		// Admin can view any scan
		scan, err = h.scannerService.GetScanByUUIDForAdmin(scanUUID)
	} else {
		// Regular user can only view their own scans (already validated by middleware)
		scan, err = h.scannerService.GetScanByUUID(scanUUID, userID)
	}
	
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id":  scan.ScanUUID,
		"status":   scan.Status,
		"progress": scan.Progress,
		"started_at":   scan.StartedAt,
		"completed_at": scan.CompletedAt,
	})
}

// GetScanResults returns the results of a specific scan by UUID
func (h *Handler) GetScanResults(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("GetScanResults called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware
	log.Printf("Getting scan results for scan %s, user %d", scanUUID, userID)
	
	// Get scan results (admin can view any scan results, regular users only their own)
	// The middleware already validates ownership for non-admin users
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	
	if err != nil {
		log.Printf("Error getting scan results: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found",
		})
		return
	}

	log.Printf("Found %d results for scan %s", len(results), scanUUID)
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"results": results,
		"count":   len(results),
	})
}

// RescanScan restarts a scan with the same parameters by UUID
func (h *Handler) RescanScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("RescanScan called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID for rescan: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Parse request body for scan parameters
	var req struct {
		MaxDepth int `json:"max_depth"`
		MaxPages int `json:"max_pages"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Error parsing rescan request: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request body",
		})
		return
	}

	// Set defaults
	if req.MaxDepth == 0 {
		req.MaxDepth = 10
	}
	if req.MaxPages == 0 {
		req.MaxPages = 20000
	}

	// Get the existing scan to get the target URL
	// Get scan (admin can rescan any scan, regular users only their own)
	var scan *database.Scan
	var err error
	if h.AuthzService.IsAdmin(userID) {
		// Admin can rescan any scan
		scan, err = h.scannerService.GetScanByUUIDForAdmin(scanUUID)
	} else {
		// Regular user can only rescan their own scans (already validated by middleware)
		scan, err = h.scannerService.GetScanByUUID(scanUUID, userID)
	}
	
	if err != nil {
		log.Printf("Error getting scan for rescan: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Scan not found or access denied",
		})
		return
	}

	// Create ScanRequest struct with the original target URL and headers
	scanReq := &scanner.ScanRequest{
		TargetURL: scan.TargetURL,
		MaxDepth:  req.MaxDepth,
		MaxPages:  req.MaxPages,
		Headers:   make(map[string]string), // Will be populated from original scan
	}
	
	// Preserve original headers from the scan
	if scan.Headers != nil && len(scan.Headers) > 0 {
		// Convert scan.Headers (map[string]interface{}) to scanReq.Headers (map[string]string)
		for k, v := range scan.Headers {
			if str, ok := v.(string); ok {
				scanReq.Headers[k] = str
			} else {
				scanReq.Headers[k] = fmt.Sprintf("%v", v)
			}
		}
		log.Printf("Rescan preserving original headers: %v", scanReq.Headers)
	} else {
		log.Printf("Rescan: No original headers found")
	}

	log.Printf("Starting rescan for scan %s, user %d", scanUUID, userID)
	response, err := h.scannerService.RescanScanByUUID(scanUUID, userID, scanReq)
	if err != nil {
		log.Printf("Error starting rescan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start rescan",
		})
		return
	}

	log.Printf("Rescan started successfully for scan %s", scanUUID)
	c.JSON(http.StatusOK, response)
}


// GetScanParameters returns all unique parameters found in a scan
func (h *Handler) GetScanParameters(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("GetScanParameters called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("Invalid scan UUID: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

	// Get scan results to extract parameters
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting scan results: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get scan results",
		})
		return
	}
	
	log.Printf("Found %d results for parameter extraction", len(results))

	// Extract unique parameters
	paramSet := make(map[string]bool)
	paramCount := 0
	formDataCount := 0
	
	for _, result := range results {
		// Extract parameters from map (already unmarshaled by GetScanResultsByUUID)
		if result.Parameters != nil {
			for param := range result.Parameters {
				log.Printf("DEBUG: Found parameter in database: '%s'", param)
				paramSet[param] = true
				paramCount++
			}
		}
		
		// Extract form data from map (already unmarshaled by GetScanResultsByUUID)
		if result.FormData != nil {
			for param := range result.FormData {
				paramSet[param] = true
				formDataCount++
			}
		}
	}

	// Convert to sorted slice and decode HTML entities
	var parameters []string
	for param := range paramSet {
		// Decode HTML entities in parameter names
		decodedParam := html.UnescapeString(param)
		log.Printf("DEBUG: Parameter '%s' -> decoded to '%s'", param, decodedParam)
		parameters = append(parameters, decodedParam)
	}
	sort.Strings(parameters)

	log.Printf("Parameter extraction complete - Total params: %d, Form data: %d, Unique params: %d", paramCount, formDataCount, len(parameters))
	
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"parameters": parameters,
		"count": len(parameters),
	})
}

// GetScanURLs returns all GET URLs found in a scan
func (h *Handler) GetScanURLs(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

	// Get scan results to extract GET URLs
	results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get scan results",
		})
		return
	}

	// Extract GET URLs
	var urls []string
	for _, result := range results {
		if result.EndpointType == "get" {
			urls = append(urls, result.URL)
		}
	}

	// Remove duplicates and sort
	urlSet := make(map[string]bool)
	for _, url := range urls {
		urlSet[url] = true
	}
	
	var uniqueURLs []string
	for url := range urlSet {
		uniqueURLs = append(uniqueURLs, url)
	}
	sort.Strings(uniqueURLs)

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"urls": uniqueURLs,
		"count": len(uniqueURLs),
	})
}

// StartParameterFuzzing starts parameter fuzzing using paramsmapper
func (h *Handler) StartParameterFuzzing(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("StartParameterFuzzing called - UserID: %d, ScanUUID: %s", userID, scanUUID)
    
    // Optional chunk size (default 500)
    chunkSize := 500
    if cs := c.Query("chunk_size"); cs != "" {
        if v, err := strconv.Atoi(cs); err == nil && v > 0 {
            chunkSize = v
        }
    }
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

    // Start parameter fuzzing in background
    go h.scannerService.RunParameterFuzzing(scanUUID, userID, chunkSize)

	c.JSON(http.StatusOK, gin.H{
		"message": "Parameter fuzzing started",
		"scan_id": scanUUID,
	})
}

// GetHiddenUrls returns paramsmapper results for a scan
func (h *Handler) GetHiddenUrls(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("GetHiddenUrls called - UserID: %d, ScanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

	// Get hidden URLs from paramsmapper reports
	hiddenUrls, err := h.scannerService.GetHiddenUrlsFromReports(scanUUID, userID)
	if err != nil {
		log.Printf("Error getting hidden URLs: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get hidden URLs",
		})
		return
	}

	log.Printf("DEBUG: Returning hidden URLs - GET: %d, POST: %d", len(hiddenUrls.GETUrls), len(hiddenUrls.POSTUrls))
	if len(hiddenUrls.GETUrls) > 0 {
		log.Printf("DEBUG: First GET URL data: %+v", hiddenUrls.GETUrls[0])
	}
	
	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanUUID,
		"get_urls": hiddenUrls.GETUrls,
		"post_urls": hiddenUrls.POSTUrls,
		"total_count": len(hiddenUrls.GETUrls) + len(hiddenUrls.POSTUrls),
	})
}

// GetFuzzingProgress returns the current fuzzing progress
func (h *Handler) GetFuzzingProgress(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	log.Printf("DEBUG: GetFuzzingProgress API called - userID: %d, scanUUID: %s", userID, scanUUID)
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		log.Printf("DEBUG: GetFuzzingProgress - invalid UUID format: %s", scanUUID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

	// Get progress from scanner service
	progress, err := h.scannerService.GetFuzzingProgress(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get fuzzing progress",
		})
		return
	}

	c.JSON(http.StatusOK, progress)
}

// StopParameterFuzzing stops the parameter fuzzing process
func (h *Handler) StopParameterFuzzing(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}
	
	// Resource ownership is already validated by middleware
	
	// Stop fuzzing process
	err := h.scannerService.StopParameterFuzzing(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to stop parameter fuzzing",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Parameter fuzzing stopped successfully",
	})
}

// CleanupOldScanData removes old numeric scan directories that are no longer needed
func (h *Handler) CleanupOldScanData(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	// Only allow admin users to perform cleanup (you can modify this logic)
	// For now, we'll allow any authenticated user, but you might want to add admin check
	
	log.Printf("CleanupOldScanData called by user %d", userID)
	
	err := h.scannerService.CleanupOldScanDirectories()
	if err != nil {
		log.Printf("Error during cleanup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to cleanup old scan data",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Old scan data cleanup completed successfully",
	})
}

// CleanupOrphanedScanFiles removes scan directories that exist on disk but not in the database
func (h *Handler) CleanupOrphanedScanFiles(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	log.Printf("CleanupOrphanedScanFiles called by user %d", userID)
	
	err := h.scannerService.CleanupOrphanedScanFiles()
	if err != nil {
		log.Printf("Error during orphaned files cleanup: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to cleanup orphaned scan files",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Orphaned scan files cleanup completed successfully",
	})
}

// DeleteAllUserScans deletes all scans for the current user
func (h *Handler) DeleteAllUserScans(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	log.Printf("DeleteAllUserScans called by user %d", userID)
	log.Printf("Request path: %s", c.Request.URL.Path)
	
	err := h.scannerService.DeleteAllScans(userID)
	if err != nil {
		log.Printf("Error during bulk scan deletion: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete all scans",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "All scans deleted successfully",
	})
}

// DeleteAllScansForAllUsers deletes ALL scans from ALL users (admin only)
func (h *Handler) DeleteAllScansForAllUsers(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	// Add admin check here if you have admin functionality
	// For now, we'll allow any authenticated user, but you should add proper admin checks
	
	log.Printf("CRITICAL: DeleteAllScansForAllUsers called by user %d", userID)
	
	err := h.scannerService.DeleteAllScansForAllUsers()
	if err != nil {
		log.Printf("Error during critical bulk scan deletion: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete all scans for all users",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "All scans for all users deleted successfully",
	})
}

// GetAllUsers retrieves all users (admin only)
// Note: Authorization is now handled by middleware, so this function is cleaner
func (h *Handler) GetAllUsers(c *gin.Context) {
	userID := c.GetInt("user_id")
	
	log.Printf("GetAllUsers called by user %d", userID)
	log.Printf("Request path: %s", c.Request.URL.Path)
	log.Printf("Request method: %s", c.Request.Method)
	
	users, err := h.scannerService.GetAllUsers()
	if err != nil {
		log.Printf("Error getting all users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get users",
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// GetUserStats retrieves statistics for a specific user (admin only)
func (h *Handler) GetUserStats(c *gin.Context) {
	userID := c.GetInt("user_id")
	targetUserIDStr := c.Param("id")
	
	// Admin access and user access are already validated by middleware
	targetUserID, err := strconv.Atoi(targetUserIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}
	
	log.Printf("GetUserStats called by admin user %d for user %d", userID, targetUserID)
	
	stats, err := h.scannerService.GetUserStats(targetUserID)
	if err != nil {
		log.Printf("Error getting user stats: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get user statistics",
		})
		return
	}
	
	c.JSON(http.StatusOK, stats)
}

// DeleteUser deletes a user and all their data (admin only)
func (h *Handler) DeleteUser(c *gin.Context) {
	userID := c.GetInt("user_id")
	targetUserIDStr := c.Param("id")
	
	// Admin access and user access are already validated by middleware
	targetUserID, err := strconv.Atoi(targetUserIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}
	
	// Prevent admin from deleting themselves
	if targetUserID == userID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Cannot delete your own account",
		})
		return
	}
	
	log.Printf("DeleteUser called by admin user %d for user %d", userID, targetUserID)
	
	err = h.scannerService.DeleteUser(targetUserID)
	if err != nil {
		log.Printf("Error deleting user: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete user",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "User deleted successfully",
	})
}

// DeleteUserScan deletes a specific scan for any user (admin only)
func (h *Handler) DeleteUserScan(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanIDStr := c.Param("id")
	
	// Admin access and resource ownership are already validated by middleware
	scanID, err := strconv.Atoi(scanIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID",
		})
		return
	}
	
	log.Printf("DeleteUserScan called by admin user %d for scan %d", userID, scanID)
	
	err = h.scannerService.DeleteUserScan(scanID)
	if err != nil {
		log.Printf("Error deleting user scan: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete scan",
			"details": err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Scan deleted successfully",
	})
}

// PromoteUserToAdmin promotes a user to admin role (admin only)
func (h *Handler) PromoteUserToAdmin(c *gin.Context) {
	userID := c.GetInt("user_id")
	targetUserIDStr := c.Param("id")
	
	// Admin access and user access are already validated by middleware
	
	targetUserID, err := strconv.Atoi(targetUserIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}
	
	// Prevent admin from promoting themselves (they're already admin)
	if targetUserID == userID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User is already an admin",
		})
		return
	}
	
	log.Printf("PromoteUserToAdmin called by admin user %d for user %d", userID, targetUserID)
	
	// Update user role to admin using scanner service
	err = h.scannerService.PromoteUserToAdmin(targetUserID)
	if err != nil {
		log.Printf("Error promoting user to admin: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to promote user to admin",
			"details": err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "User promoted to admin successfully",
	})
}

// ExportHiddenUrls exports hidden URLs in TXT format with only URL values
func (h *Handler) ExportHiddenUrls(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	// Resource ownership is already validated by middleware

	// Get hidden URLs
	hiddenUrls, err := h.scannerService.GetHiddenUrlsFromReports(scanUUID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to get hidden URLs",
		})
		return
	}

	// Extract only URL values from the response
	var urls []string
	
	// Add GET URLs
	for _, urlData := range hiddenUrls.GETUrls {
		if url, ok := urlData["url"].(string); ok && url != "" {
			urls = append(urls, url)
		}
	}
	
	// Add POST URLs
	for _, urlData := range hiddenUrls.POSTUrls {
		if url, ok := urlData["url"].(string); ok && url != "" {
			urls = append(urls, url)
		}
	}

	// Create TXT content with one URL per line
	txtContent := strings.Join(urls, "\n")
	
	// Set headers for TXT file download
	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=hidden_urls_%s.txt", scanUUID))
	
	// Return the TXT content
	c.String(http.StatusOK, txtContent)
}

// ExportScanResults exports scan results in various formats
func (h *Handler) ExportScanResults(c *gin.Context) {
	userID := c.GetInt("user_id")
	scanUUID := c.Param("id")
	
	// Validate UUID format
	if !isValidUUID(scanUUID) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid scan ID format",
		})
		return
	}

	format := c.Query("format")
	if format == "" {
		format = "json"
	}

	// Resource ownership is already validated by middleware

	// For now, return JSON format
	// TODO: Implement CSV and other export formats
	if format == "json" {
		results, err := h.scannerService.GetScanResultsByUUID(scanUUID, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to export results",
			})
			return
		}

		c.Header("Content-Type", "application/json")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=scan_results_%s.json", scanUUID))
		c.JSON(http.StatusOK, gin.H{
			"scan_id": scanUUID,
			"results": results,
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported export format",
		})
	}
}

// GetDashboardStats returns dashboard statistics
func (h *Handler) GetDashboardStats(c *gin.Context) {
	userID := c.GetInt("user_id")

	stats, err := h.scannerService.GetDashboardStats(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve dashboard statistics",
		})
		return
	}

	c.JSON(http.StatusOK, stats)
}
