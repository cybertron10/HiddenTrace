package main

import (
	"log"
	"net/http"
	"os"

	"HiddenTrace/web/internal/api"
	"HiddenTrace/web/internal/auth"
	"HiddenTrace/web/internal/database"
	"HiddenTrace/web/internal/middleware"
	"HiddenTrace/web/internal/scanner"
	"HiddenTrace/web/internal/session"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize database
	db, err := database.Initialize()
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	// Initialize session service
	sessionService := session.NewService(db)
	err = sessionService.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize session service: %v", err)
	}

	// Initialize scanner service
	scannerService := scanner.NewService(db)

	// Initialize auth service
	authService := auth.NewService(db, sessionService)

	// Initialize API handlers
	apiHandler := api.NewHandler(scannerService, authService)

	// Setup Gin router
	r := gin.Default()

	// Security headers middleware
	r.Use(middleware.SecurityHeadersMiddleware())
	r.Use(middleware.CSPMiddleware())

	// CORS configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000", "http://localhost:8080", "http://16.170.226.104:8080"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"}
	config.AllowCredentials = true
	config.AllowWildcard = true
	r.Use(cors.New(config))

	// Static files
	r.Static("/static", "./web/static")
	r.LoadHTMLGlob("web/templates/*")

	// Routes
	setupRoutes(r, apiHandler, authService, sessionService, scannerService)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	address := host + ":" + port
	log.Printf("🚀 HiddenTrace Web Server starting on %s", address)
	log.Fatal(http.ListenAndServe(address, r))
}

func setupRoutes(r *gin.Engine, apiHandler *api.Handler, authService *auth.Service, sessionService *session.Service, scannerService *scanner.Service) {
	log.Println("🚀 Setting up routes...")
	
	// Create a closure for getScanOwner that captures the scanner service
	getScanOwner := func(scanUUID string) (int, error) {
		return scannerService.GetScanOwner(scanUUID)
	}
    // Root: redirect based on session presence
    r.GET("/", func(c *gin.Context) {
        if sessionID, err := c.Cookie("JSESSIONID"); err == nil {
            if _, err := sessionService.GetSession(sessionID); err == nil {
                c.Redirect(http.StatusFound, "/dashboard")
                return
            }
        }
        c.Redirect(http.StatusFound, "/login")
    })

    // Login page (public): show landing/index
    r.GET("/login", func(c *gin.Context) {
        c.HTML(http.StatusOK, "index.html", gin.H{
            "title": "HiddenTrace - Login",
            "nonce": middleware.GetNonce(c),
        })
    })

    // Dashboard route (protected with session)
    r.GET("/dashboard", middleware.SessionRequired(sessionService), func(c *gin.Context) {
        c.HTML(http.StatusOK, "dashboard.html", gin.H{
            "title": "HiddenTrace Dashboard",
            "nonce": middleware.GetNonce(c),
        })
    })

    // Admin Panel page (session + admin)
    r.GET("/admin", middleware.AdminSessionRequired(sessionService, authService), func(c *gin.Context) {
        c.HTML(http.StatusOK, "dashboard.html", gin.H{
            "title": "Admin Panel",
            "nonce": middleware.GetNonce(c),
        })
    })

	// Scan Results route (protected with session)
	r.GET("/scan-results/:id", middleware.SessionRequired(sessionService), func(c *gin.Context) {
		c.HTML(http.StatusOK, "scan-results.html", gin.H{
			"title": "Scan Results",
			"nonce": middleware.GetNonce(c),
		})
	})

	// API routes
	log.Println("Creating API group...")
	api := r.Group("/api")
	{
		// Authentication routes
		auth := api.Group("/auth")
		{
			auth.POST("/register", apiHandler.Register)
			auth.POST("/login", apiHandler.Login)
			auth.POST("/logout", middleware.SessionAndAuthRequired(sessionService, authService), apiHandler.Logout)
			auth.GET("/me", middleware.SessionAndAuthRequired(sessionService, authService), apiHandler.GetProfile)
		}

		// Scanner routes (protected with hybrid auth)
		scanner := api.Group("/scanner")
		scanner.Use(middleware.SessionAndAuthRequired(sessionService, authService))
		{
			log.Println("Scanner group created, registering scanner routes...")
			// User operations (no additional middleware needed - users can only access their own data)
			scanner.POST("/scan", apiHandler.StartScan)
			scanner.GET("/scans", apiHandler.GetScans)
			scanner.DELETE("/scans/bulk/all", apiHandler.DeleteAllUserScans)
			
			// Scan-specific operations with resource ownership validation
			scanner.GET("/scans/:id", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetScan)
			scanner.DELETE("/scans/:id", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.DeleteScan)
			scanner.POST("/scans/:id/rescan", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.RescanScan)
			scanner.GET("/scans/:id/status", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetScanStatus)
			scanner.GET("/scans/:id/results", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetScanResults)
			scanner.GET("/scans/:id/parameters", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetScanParameters)
			scanner.GET("/scans/:id/urls", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetScanURLs)
			scanner.POST("/scans/:id/fuzz", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.StartParameterFuzzing)
			scanner.GET("/scans/:id/hidden-urls", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetHiddenUrls)
			scanner.GET("/scans/:id/hidden-urls/export", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.ExportHiddenUrls)
			scanner.GET("/scans/:id/fuzz/progress", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetFuzzingProgress)
			scanner.POST("/scans/:id/fuzz/stop", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.StopParameterFuzzing)
			scanner.GET("/scans/:id/export", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.ExportScanResults)
			
			// Axiom scan routes
			scanner.POST("/scans/:id/axiom-scan", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.StartAxiomScan)
			scanner.GET("/scans/:id/axiom-scan/status", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetAxiomScanStatus)
			scanner.GET("/scans/:id/axiom-scan/results", 
				apiHandler.AuthzService.RequireResourceOwnership(getScanOwner), 
				apiHandler.GetAxiomScanResults)
			
			log.Println("About to create admin group...")
			// Admin-only routes with centralized authorization
			admin := scanner.Group("/admin")
			log.Println("Admin group created successfully")
			admin.Use(apiHandler.AuthzService.RequireAdmin()) // Centralized admin authorization
			{
				log.Println("Registering admin routes...")
				// System operations with specific permissions
				admin.POST("/cleanup-old-scans", apiHandler.AuthzService.RequirePermission("system_operations"), apiHandler.CleanupOldScanData)
				admin.POST("/cleanup-orphaned-files", apiHandler.AuthzService.RequirePermission("system_operations"), apiHandler.CleanupOrphanedScanFiles)
				admin.DELETE("/scans/bulk/all", apiHandler.AuthzService.RequirePermission("delete_all_scans"), apiHandler.DeleteAllScansForAllUsers)
				// User management routes with specific permissions
				admin.GET("/users", apiHandler.AuthzService.RequirePermission("view_all_users"), apiHandler.GetAllUsers)
				admin.GET("/users/:id/stats", 
					apiHandler.AuthzService.RequirePermission("view_all_users"),
					apiHandler.AuthzService.RequireUserAccess(),
					apiHandler.GetUserStats)
				admin.DELETE("/users/:id", 
					apiHandler.AuthzService.RequirePermission("manage_users"),
					apiHandler.AuthzService.RequireUserAccess(),
					apiHandler.DeleteUser)
				admin.POST("/users/:id/promote", 
					apiHandler.AuthzService.RequirePermission("manage_users"),
					apiHandler.AuthzService.RequireUserAccess(),
					apiHandler.PromoteUserToAdmin)
				admin.DELETE("/scans/:id", 
					apiHandler.AuthzService.RequirePermission("delete_all_scans"),
					apiHandler.AuthzService.RequireResourceOwnership(getScanOwner),
					apiHandler.DeleteUserScan)
				
				// Debug route to test admin access
				admin.GET("/test", func(c *gin.Context) {
					userID := c.GetInt("user_id")
					c.JSON(200, gin.H{
						"message": "Admin test route working",
						"user_id": userID,
						"is_admin": false, // This will be determined by role check
					})
				})
				log.Println("Admin routes registered successfully")
			}
		}


		// Dashboard routes (protected with hybrid auth)
		dashboard := api.Group("/dashboard")
		dashboard.Use(middleware.SessionAndAuthRequired(sessionService, authService))
		{
			dashboard.GET("/stats", apiHandler.GetDashboardStats)
		}

	}
}

