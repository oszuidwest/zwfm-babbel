// Package api provides HTTP routing and middleware setup for the Babbel API server.
package api

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

// SetupRouter configures and returns the main API router with all routes and middleware.
// Creates a complete Gin router with authentication, CORS, session management, and all API endpoints.
// The router is configured with role-based access control and comprehensive error handling.
//
// Authentication methods supported:
//   - Local username/password authentication
//   - OAuth/OIDC authentication
//   - Combined authentication (both methods enabled)
//
// Returns a configured Gin engine ready for HTTP serving, or an error if setup fails.
func SetupRouter(db *sqlx.DB, gormDB *gorm.DB, cfg *config.Config) (*gin.Engine, error) {
	// Create transaction manager
	txManager := repository.NewTxManager(db)

	// Create repositories (GORM-based repositories use gormDB, legacy use db)
	stationRepo := repository.NewStationRepository(gormDB)
	voiceRepo := repository.NewVoiceRepository(gormDB)
	userRepo := repository.NewUserRepository(gormDB)
	storyRepo := repository.NewStoryRepository(gormDB)
	bulletinRepo := repository.NewBulletinRepository(gormDB)
	stationVoiceRepo := repository.NewStationVoiceRepository(gormDB)
	audioRepo := repository.NewAudioRepository(db)

	// Create audio service
	audioSvc := audio.NewService(cfg)

	// Create domain services with repositories
	bulletinSvc := services.NewBulletinService(services.BulletinServiceDeps{
		TxManager:    txManager,
		BulletinRepo: bulletinRepo,
		StationRepo:  stationRepo,
		StoryRepo:    storyRepo,
		AudioSvc:     audioSvc,
		Config:       cfg,
		GormDB:       gormDB,
	})
	storySvc := services.NewStoryService(services.StoryServiceDeps{
		StoryRepo: storyRepo,
		VoiceRepo: voiceRepo,
		AudioSvc:  audioSvc,
		Config:    cfg,
	})
	stationSvc := services.NewStationService(stationRepo, gormDB)
	voiceSvc := services.NewVoiceService(voiceRepo, gormDB)
	userSvc := services.NewUserService(userRepo, gormDB)
	stationVoiceSvc := services.NewStationVoiceService(services.StationVoiceServiceDeps{
		StationVoiceRepo: stationVoiceRepo,
		StationRepo:      stationRepo,
		VoiceRepo:        voiceRepo,
		AudioSvc:         audioSvc,
		Config:           cfg,
		GormDB:           gormDB,
	})

	// Create handlers with services and audio repository
	h := handlers.NewHandlers(handlers.HandlersDeps{
		AudioRepo:       audioRepo,
		AudioSvc:        audioSvc,
		Config:          cfg,
		BulletinSvc:     bulletinSvc,
		StorySvc:        storySvc,
		StationSvc:      stationSvc,
		VoiceSvc:        voiceSvc,
		UserSvc:         userSvc,
		StationVoiceSvc: stationVoiceSvc,
	})

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
			Enabled:                cfg.Auth.Method.SupportsLocal(),
			MinPasswordLength:      cfg.Auth.Local.MinPasswordLength,
			RequireUppercase:       cfg.Auth.Local.RequireUppercase,
			RequireLowercase:       cfg.Auth.Local.RequireLowercase,
			RequireNumbers:         cfg.Auth.Local.RequireNumber,
			MaxFailedAttempts:      cfg.Auth.Local.MaxLoginAttempts,
			LockoutDurationMinutes: cfg.Auth.Local.LockoutDurationMinutes,
		},
		Session: auth.SessionConfig{
			StoreType:      "memory",
			MaxAge:         86400,
			CookieName:     "babbel_session",
			CookiePath:     "/",
			CookieDomain:   cfg.Auth.CookieDomain,
			CookieSecure:   cfg.Environment == "production",
			CookieHTTPOnly: true,
			CookieSameSite: string(cfg.Auth.CookieSameSite),
			SecretKey:      cfg.Auth.SessionSecret,
		},
		AllowedOrigins: cfg.Server.AllowedOrigins,
	}

	// Create auth service
	authService, err := auth.NewService(authConfig, db)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Get frontend URL from environment (required if using OAuth)
	frontendURL := getEnv("BABBEL_FRONTEND_URL", "")
	if frontendURL == "" && cfg.Auth.Method.SupportsOIDC() {
		return nil, fmt.Errorf("BABBEL_FRONTEND_URL is required when OAuth/OIDC is enabled")
	}
	authHandlers := NewAuthHandlers(authService, frontendURL, h)

	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize custom validators
	utils.InitializeValidators()

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

		// Authentication endpoints - RESTful resource-based
		// Sessions are resources that can be created (login) and deleted (logout)
		v1.POST("/sessions", authHandlers.Login)                         // Create session (login)
		v1.GET("/auth/oauth", authHandlers.StartOAuthFlow)               // OAuth initiation
		v1.GET("/auth/oauth/callback", authHandlers.HandleOAuthCallback) // OAuth callback

		// Protected routes
		protected := v1.Group("")
		protected.Use(authService.Middleware())
		{
			// Session management - RESTful
			protected.DELETE("/sessions/current", authHandlers.Logout)      // Delete current session
			protected.GET("/sessions/current", authHandlers.GetCurrentUser) // Get current session

			// Station routes
			protected.GET("/stations", authService.RequirePermission(auth.ResourceStations, auth.ActionRead), h.ListStations)
			protected.GET("/stations/:id", authService.RequirePermission(auth.ResourceStations, auth.ActionRead), h.GetStation)
			protected.POST("/stations", authService.RequirePermission(auth.ResourceStations, auth.ActionWrite), h.CreateStation)
			protected.PUT("/stations/:id", authService.RequirePermission(auth.ResourceStations, auth.ActionWrite), h.UpdateStation)
			protected.DELETE("/stations/:id", authService.RequirePermission(auth.ResourceStations, auth.ActionWrite), h.DeleteStation)

			// Voice routes
			protected.GET("/voices", authService.RequirePermission(auth.ResourceVoices, auth.ActionRead), h.ListVoices)
			protected.GET("/voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionRead), h.GetVoice)
			protected.POST("/voices", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.CreateVoice)
			protected.PUT("/voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.UpdateVoice)
			protected.DELETE("/voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.DeleteVoice)

			// Story routes
			protected.GET("/stories", authService.RequirePermission(auth.ResourceStories, auth.ActionRead), h.ListStories)
			protected.GET("/stories/:id", authService.RequirePermission(auth.ResourceStories, auth.ActionRead), h.GetStory)
			protected.GET("/stories/:id/audio", authService.RequirePermission(auth.ResourceStories, auth.ActionRead), func(c *gin.Context) {
				h.ServeAudio(c, handlers.AudioConfig{
					TableName:   "stories",
					IDColumn:    "id",
					FileColumn:  "audio_file",
					FilePrefix:  "story",
					ContentType: "audio/wav",
					Directory:   "processed",
				})
			})
			protected.POST("/stories", authService.RequirePermission(auth.ResourceStories, auth.ActionWrite), h.CreateStory)
			protected.PUT("/stories/:id", authService.RequirePermission(auth.ResourceStories, auth.ActionWrite), h.UpdateStory)
			protected.DELETE("/stories/:id", authService.RequirePermission(auth.ResourceStories, auth.ActionWrite), h.DeleteStory)
			protected.PATCH("/stories/:id", authService.RequirePermission(auth.ResourceStories, auth.ActionWrite), h.UpdateStoryStatus)

			// User routes (admin only)
			protected.GET("/users", authService.RequirePermission(auth.ResourceUsers, auth.ActionRead), h.ListUsers)
			protected.GET("/users/:id", authService.RequirePermission(auth.ResourceUsers, auth.ActionRead), h.GetUser)
			protected.POST("/users", authService.RequirePermission(auth.ResourceUsers, auth.ActionWrite), h.CreateUser)
			protected.PUT("/users/:id", authService.RequirePermission(auth.ResourceUsers, auth.ActionWrite), h.UpdateUser)
			protected.DELETE("/users/:id", authService.RequirePermission(auth.ResourceUsers, auth.ActionWrite), h.DeleteUser)
			protected.PATCH("/users/:id", authService.RequirePermission(auth.ResourceUsers, auth.ActionWrite), h.UpdateUserStatus)
			// Password change should be part of user update
			// PATCH /users/:id with {"password": "newpass"}

			// Station-Voice routes - RESTful naming with hyphens
			protected.GET("/station-voices", authService.RequirePermission(auth.ResourceVoices, auth.ActionRead), h.ListStationVoices)
			protected.GET("/station-voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionRead), h.GetStationVoice)
			protected.GET("/station-voices/:id/audio", authService.RequirePermission(auth.ResourceVoices, auth.ActionRead), func(c *gin.Context) {
				h.ServeAudio(c, handlers.AudioConfig{
					TableName:   "station_voices",
					IDColumn:    "id",
					FileColumn:  "audio_file",
					FilePrefix:  "jingle",
					ContentType: "audio/wav",
					Directory:   "processed",
				})
			})
			protected.POST("/station-voices", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.CreateStationVoice)
			protected.PUT("/station-voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.UpdateStationVoice)
			protected.DELETE("/station-voices/:id", authService.RequirePermission(auth.ResourceVoices, auth.ActionWrite), h.DeleteStationVoice)

			// Bulletin routes - RESTful (no verbs in URLs)
			protected.GET("/bulletins", authService.RequirePermission(auth.ResourceBulletins, auth.ActionRead), h.ListBulletins)
			protected.POST("/stations/:id/bulletins", authService.RequirePermission(auth.ResourceBulletins, auth.ActionGenerate), h.GenerateBulletin) // Create bulletin
			protected.GET("/stations/:id/bulletins", authService.RequirePermission(auth.ResourceBulletins, auth.ActionRead), h.GetStationBulletins)   // List station bulletins
			protected.GET("/bulletins/:id/audio", authService.RequirePermission(auth.ResourceBulletins, auth.ActionRead), h.GetBulletinAudio)

			// Story bulletin history
			protected.GET("/stories/:id/bulletins", authService.RequirePermission(auth.ResourceStories, auth.ActionRead), h.GetStoryBulletinHistory)

			// Stories included in bulletins
			protected.GET("/bulletins/:id/stories", authService.RequirePermission(auth.ResourceStories, auth.ActionRead), h.GetBulletinStories)
		}
	}

	// Health check (typed response for compile-time safety)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, handlers.HealthResponse{
			Status:  "ok",
			Service: "babbel-api",
		})
	})

	return r, nil
}

// corsMiddleware creates a CORS middleware that respects the configured allowed origins.
// Provides secure CORS handling by default (disabled unless origins are explicitly configured).
// When enabled, supports credentials and common HTTP methods for API access.
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

// isAllowedOrigin checks if the origin is in the comma-separated list of allowed origins.
func isAllowedOrigin(origin string, allowedOrigins string) bool {
	if origin == "" {
		return false
	}

	// Split and trim the allowed origins
	origins := strings.Split(allowedOrigins, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	return slices.Contains(origins, origin)
}

// getEnv retrieves an environment variable with fallback to default value if unset.
// Utility function for configuration loading within the router setup.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
