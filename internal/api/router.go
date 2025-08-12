package api

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// SetupRouter configures and returns the main API router with all routes and middleware.
func SetupRouter(db *sqlx.DB, cfg *config.Config) *gin.Engine {
	// Create services
	audioSvc := audio.NewService(cfg)
	h := handlers.NewHandlers(db, audioSvc, cfg)

	// Create auth configuration
	authConfig := &auth.Config{
		Method: cfg.Auth.Method,
		OIDC: auth.OIDCConfig{
			ProviderURL:  cfg.Auth.OIDCProviderURL,
			ClientID:     cfg.Auth.OIDCClientID,
			ClientSecret: cfg.Auth.OIDCClientSecret,
			RedirectURL:  cfg.Auth.OIDCRedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
		},
		Local: auth.LocalConfig{
			Enabled:                cfg.Auth.Method == "local" || cfg.Auth.Method == "both",
			MinPasswordLength:      8,
			RequireUppercase:       true,
			RequireLowercase:       true,
			RequireNumbers:         true,
			MaxFailedAttempts:      5,
			LockoutDurationMinutes: 30,
		},
		Session: auth.SessionConfig{
			StoreType:      "memory",
			MaxAge:         86400,
			CookieName:     "babbel_session",
			CookiePath:     "/",
			CookieDomain:   cfg.Auth.CookieDomain,
			CookieSecure:   cfg.Environment == "production",
			CookieHTTPOnly: true,
			CookieSameSite: cfg.Auth.CookieSameSite,
			SecretKey:      cfg.Auth.SessionSecret,
		},
	}

	// Create auth service
	authService, err := auth.NewService(authConfig, db)
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}

	// Get frontend URL from environment (required if using OAuth)
	frontendURL := getEnv("BABBEL_FRONTEND_URL", "")
	if frontendURL == "" && (cfg.Auth.Method == "oidc" || cfg.Auth.Method == "both") {
		log.Fatalf("BABBEL_FRONTEND_URL is required when OAuth/OIDC is enabled")
	}
	authHandlers := NewAuthHandlers(authService, frontendURL, h)

	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Create router
	r := gin.Default()

	// Session middleware - must be first
	r.Use(authService.SessionMiddleware())

	// CORS middleware
	r.Use(corsMiddleware(cfg))

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		// Authentication configuration (public)
		v1.GET("/auth/config", authHandlers.GetAuthConfig)

		// Authentication endpoints (keep SSO functionality)
		authGroup := v1.Group("/session")
		{
			authGroup.POST("/login", authHandlers.Login)
			authGroup.GET("/oauth/start", authHandlers.StartOAuthFlow)
			authGroup.GET("/oauth/callback", authHandlers.HandleOAuthCallback)
		}

		// Protected routes
		protected := v1.Group("")
		protected.Use(authService.Middleware())
		{
			// Session management
			protected.DELETE("/session", authHandlers.Logout)
			protected.GET("/session", authHandlers.GetCurrentUser)

			// Station routes
			protected.GET("/stations", authService.RequirePermission("stations", "read"), h.ListStations)
			protected.GET("/stations/:id", authService.RequirePermission("stations", "read"), h.GetStation)
			protected.POST("/stations", authService.RequirePermission("stations", "write"), h.CreateStation)
			protected.PUT("/stations/:id", authService.RequirePermission("stations", "write"), h.UpdateStation)
			protected.DELETE("/stations/:id", authService.RequirePermission("stations", "write"), h.DeleteStation)

			// Voice routes
			protected.GET("/voices", authService.RequirePermission("voices", "read"), h.ListVoices)
			protected.GET("/voices/:id", authService.RequirePermission("voices", "read"), h.GetVoice)
			protected.POST("/voices", authService.RequirePermission("voices", "write"), h.CreateVoice)
			protected.PUT("/voices/:id", authService.RequirePermission("voices", "write"), h.UpdateVoice)
			protected.DELETE("/voices/:id", authService.RequirePermission("voices", "write"), h.DeleteVoice)

			// Story routes
			protected.GET("/stories", authService.RequirePermission("stories", "read"), h.ListStories)
			protected.GET("/stories/:id", authService.RequirePermission("stories", "read"), h.GetStory)
			protected.GET("/stories/:id/audio", authService.RequirePermission("stories", "read"), func(c *gin.Context) {
				h.ServeAudio(c, handlers.AudioConfig{
					TableName:   "stories",
					IDColumn:    "id",
					FileColumn:  "audio_file",
					FilePrefix:  "story",
					ContentType: "audio/wav",
				})
			})
			protected.POST("/stories", authService.RequirePermission("stories", "write"), h.CreateStory)
			protected.PUT("/stories/:id", authService.RequirePermission("stories", "write"), h.UpdateStory)
			protected.DELETE("/stories/:id", authService.RequirePermission("stories", "write"), func(c *gin.Context) {
				id, ok := utils.GetIDParam(c)
				if !ok {
					return
				}
				if !utils.ValidateResourceExists(c, db, "stories", "Story", id) {
					return
				}
				_, err := db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete story"})
					return
				}
				c.JSON(http.StatusNoContent, nil)
			})
			protected.PATCH("/stories/:id", authService.RequirePermission("stories", "write"), func(c *gin.Context) {
				id, ok := utils.GetIDParam(c)
				if !ok {
					return
				}
				if !utils.ValidateResourceExists(c, db, "stories", "Story", id) {
					return
				}

				// Support both status updates and soft delete/restore
				var req struct {
					Status    *string `json:"status"`
					DeletedAt *string `json:"deleted_at"`
				}
				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: " + err.Error()})
					return
				}

				// Validate that at least one field is provided
				if req.Status == nil && req.DeletedAt == nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "At least one field (status or deleted_at) is required"})
					return
				}

				// Validate status field if provided
				if req.Status != nil {
					validStatuses := []string{"draft", "active", "expired"}
					isValid := false
					for _, validStatus := range validStatuses {
						if *req.Status == validStatus {
							isValid = true
							break
						}
					}
					if !isValid {
						c.JSON(http.StatusBadRequest, gin.H{"error": "Status must be one of: draft, active, expired"})
						return
					}
				}

				// Handle soft delete/restore
				if req.DeletedAt != nil {
					if *req.DeletedAt == "" {
						// Restore story (set deleted_at to NULL)
						_, err := db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NULL WHERE id = ?", id)
						if err != nil {
							c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to restore story"})
							return
						}
						c.JSON(http.StatusOK, gin.H{"message": "Story restored"})
						return
					} else {
						// Soft delete story (set deleted_at to NOW())
						_, err := db.ExecContext(c.Request.Context(), "UPDATE stories SET deleted_at = NOW() WHERE id = ?", id)
						if err != nil {
							c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to soft delete story"})
							return
						}
						c.Status(http.StatusNoContent)
						return
					}
				}

				// Handle status update
				if req.Status != nil {
					_, err := db.ExecContext(c.Request.Context(), "UPDATE stories SET status = ? WHERE id = ?", *req.Status, id)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update story status"})
						return
					}
					c.JSON(http.StatusOK, gin.H{"message": "Story status updated"})
				}
			})

			// User routes (admin only)
			protected.GET("/users", authService.RequirePermission("users", "read"), h.ListUsers)
			protected.GET("/users/:id", authService.RequirePermission("users", "read"), h.GetUser)
			protected.POST("/users", authService.RequirePermission("users", "write"), h.CreateUser)
			protected.PUT("/users/:id", authService.RequirePermission("users", "write"), h.UpdateUser)
			protected.DELETE("/users/:id", authService.RequirePermission("users", "write"), h.DeleteUser)
			protected.PATCH("/users/:id", authService.RequirePermission("users", "write"), func(c *gin.Context) {
				id, ok := utils.GetIDParam(c)
				if !ok {
					return
				}
				if !utils.ValidateResourceExists(c, db, "users", "User", id) {
					return
				}
				var req struct {
					Action string `json:"action" binding:"required,oneof=suspend restore"`
				}
				if !utils.BindAndValidate(c, &req) {
					return
				}
				query := "UPDATE users SET suspended_at = NOW() WHERE id = ?"
				if req.Action == "restore" {
					query = "UPDATE users SET suspended_at = NULL WHERE id = ?"
				}
				_, err := db.ExecContext(c.Request.Context(), query, id)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user state"})
					return
				}
				c.JSON(http.StatusOK, gin.H{"message": "User state updated"})
			})
			protected.PUT("/users/:id/password", authService.RequirePermission("users", "write"), h.ChangePassword)

			// Station-Voice routes (for managing station-specific jingles)
			protected.GET("/station_voices", authService.RequirePermission("voices", "read"), h.ListStationVoices)
			protected.GET("/station_voices/:id", authService.RequirePermission("voices", "read"), h.GetStationVoice)
			protected.GET("/station_voices/:id/audio", authService.RequirePermission("voices", "read"), func(c *gin.Context) {
				h.ServeAudio(c, handlers.AudioConfig{
					TableName:   "station_voices",
					IDColumn:    "id",
					FileColumn:  "jingle_file",
					FilePrefix:  "jingle",
					ContentType: "audio/wav",
				})
			})
			protected.POST("/station_voices", authService.RequirePermission("voices", "write"), h.CreateStationVoice)
			protected.PUT("/station_voices/:id", authService.RequirePermission("voices", "write"), h.UpdateStationVoice)
			protected.DELETE("/station_voices/:id", authService.RequirePermission("voices", "write"), h.DeleteStationVoice)

			// Bulletin routes
			protected.GET("/bulletins", authService.RequirePermission("bulletins", "read"), h.ListBulletins)
			protected.POST("/stations/:id/bulletins/generate", authService.RequirePermission("bulletins", "generate"), h.GenerateBulletin)
			protected.GET("/stations/:id/bulletins/latest", authService.RequirePermission("bulletins", "read"), h.GetLatestBulletin)
			protected.GET("/stations/:id/bulletins/latest/audio", authService.RequirePermission("bulletins", "read"), h.GetLatestBulletinAudio)
			protected.GET("/bulletins/:id/audio", authService.RequirePermission("bulletins", "read"), h.GetBulletinAudio)

			// Story bulletin history
			protected.GET("/stories/:id/bulletins", authService.RequirePermission("stories", "read"), h.GetStoryBulletinHistory)

			// Stories included in bulletins
			protected.GET("/bulletins/:id/stories", authService.RequirePermission("stories", "read"), h.GetBulletinStories)
		}
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "babbel-api",
		})
	})

	return r
}

func corsMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// If no allowed origins are configured, disable CORS (secure by default)
		if cfg.Server.AllowedOrigins == "" {
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
			c.Next()
			return
		}

		// Check if the origin is in the allowed list
		if isAllowedOrigin(origin, cfg.Server.AllowedOrigins) {
			// Delete any existing CORS headers that might be set by proxies
			c.Writer.Header().Del("Access-Control-Allow-Origin")
			c.Writer.Header().Del("Access-Control-Allow-Credentials")
			c.Writer.Header().Del("Access-Control-Allow-Headers")
			c.Writer.Header().Del("Access-Control-Allow-Methods")

			// Set our CORS headers
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// isAllowedOrigin checks if the origin is in the comma-separated list of allowed origins
func isAllowedOrigin(origin string, allowedOrigins string) bool {
	if origin == "" {
		return false
	}

	// Split the allowed origins by comma
	origins := strings.Split(allowedOrigins, ",")
	for _, allowed := range origins {
		allowed = strings.TrimSpace(allowed)
		if allowed == origin {
			return true
		}
	}

	return false
}

// getEnv gets environment variable with default fallback
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
