// Package api provides HTTP routing and middleware setup for the Babbel API server.
package api

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

// routerDeps holds the resolved dependencies needed for route registration.
type routerDeps struct {
	handlers          *handlers.Handlers
	automationHandler *handlers.AutomationHandler
	authHandlers      *AuthHandlers
	authService       *auth.Service
}

// SetupRouter configures and returns the main API router with all routes and middleware.
func SetupRouter(db *gorm.DB, cfg *config.Config) (*gin.Engine, error) {
	deps, err := buildDependencies(db, cfg)
	if err != nil {
		return nil, err
	}

	// Set Gin mode based on environment
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize custom validators
	utils.InitializeValidators()

	r := setupEngine(cfg, deps.authService)
	registerPublicRoutes(r, deps)
	registerAPIRoutes(r, deps)
	registerHealthRoute(r)

	return r, nil
}

// buildDependencies creates all services and handlers needed by the router.
func buildDependencies(db *gorm.DB, cfg *config.Config) (*routerDeps, error) {
	txManager := repository.NewTxManager(db)

	// Create repositories
	stationRepo := repository.NewStationRepository(db)
	voiceRepo := repository.NewVoiceRepository(db)
	userRepo := repository.NewUserRepository(db)
	storyRepo := repository.NewStoryRepository(db)
	bulletinRepo := repository.NewBulletinRepository(db)
	stationVoiceRepo := repository.NewStationVoiceRepository(db)
	audioRepo := repository.NewAudioRepository(db)

	// Create audio and TTS services
	audioSvc := audio.NewService(cfg)
	ttsSvc := tts.NewService(&cfg.TTS)

	// Create domain services
	bulletinSvc := services.NewBulletinService(services.BulletinServiceDeps{
		TxManager:    txManager,
		BulletinRepo: bulletinRepo,
		StationRepo:  stationRepo,
		StoryRepo:    storyRepo,
		AudioSvc:     audioSvc,
		Config:       cfg,
	})
	storySvc := services.NewStoryService(services.StoryServiceDeps{
		StoryRepo: storyRepo,
		VoiceRepo: voiceRepo,
		AudioSvc:  audioSvc,
		TTSSvc:    ttsSvc,
		Config:    cfg,
	})
	stationSvc := services.NewStationService(stationRepo)
	voiceSvc := services.NewVoiceService(voiceRepo)
	userSvc := services.NewUserService(userRepo)
	stationVoiceSvc := services.NewStationVoiceService(services.StationVoiceServiceDeps{
		TxManager:        txManager,
		StationVoiceRepo: stationVoiceRepo,
		StationRepo:      stationRepo,
		VoiceRepo:        voiceRepo,
		AudioSvc:         audioSvc,
		Config:           cfg,
	})

	// Create handlers
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
		TTSEnabled:      ttsSvc != nil,
	})
	automationHandler := handlers.NewAutomationHandler(bulletinSvc, stationSvc, cfg)

	// Create auth service
	authService, err := auth.NewService(buildAuthConfig(cfg), db)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}

	// Get frontend URL from environment (required if using OAuth)
	frontendURL := getEnv("BABBEL_FRONTEND_URL", "")
	if frontendURL == "" && cfg.Auth.Method.SupportsOIDC() {
		return nil, fmt.Errorf("BABBEL_FRONTEND_URL is required when OAuth/OIDC is enabled")
	}

	return &routerDeps{
		handlers:          h,
		automationHandler: automationHandler,
		authHandlers:      NewAuthHandlers(authService, frontendURL, h),
		authService:       authService,
	}, nil
}

// buildAuthConfig constructs the auth configuration from the application config.
func buildAuthConfig(cfg *config.Config) *auth.Config {
	return &auth.Config{
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
}

// setupEngine creates the Gin engine with global middleware.
func setupEngine(cfg *config.Config, authService *auth.Service) *gin.Engine {
	r := gin.New()
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipQueryString: true,
	}))
	r.Use(gin.Recovery())
	r.Use(authService.SessionMiddleware())
	r.Use(securityHeaders(cfg))
	r.Use(corsMiddleware(cfg))
	return r
}

// registerPublicRoutes registers unauthenticated public endpoints.
func registerPublicRoutes(r *gin.Engine, deps *routerDeps) {
	public := r.Group("/public")
	public.GET("/stations/:id/bulletin.wav", deps.automationHandler.GetPublicBulletin)
}

// registerAPIRoutes registers all versioned API routes.
func registerAPIRoutes(r *gin.Engine, deps *routerDeps) {
	v1 := r.Group("/api/v1")

	registerAuthRoutes(v1, deps)

	protected := v1.Group("")
	protected.Use(deps.authService.Middleware())

	registerSessionRoutes(protected, deps)
	registerStationRoutes(protected, deps)
	registerVoiceRoutes(protected, deps)
	registerStoryRoutes(protected, deps)
	registerUserRoutes(protected, deps)
	registerStationVoiceRoutes(protected, deps)
	registerBulletinRoutes(protected, deps)
}

// registerAuthRoutes registers public authentication endpoints.
func registerAuthRoutes(v1 *gin.RouterGroup, deps *routerDeps) {
	v1.GET("/auth/config", deps.authHandlers.GetAuthConfig)
	v1.POST("/sessions", deps.authHandlers.Login)
	v1.GET("/auth/oauth", deps.authHandlers.StartOAuthFlow)
	v1.GET("/auth/oauth/callback", deps.authHandlers.HandleOAuthCallback)
}

// registerSessionRoutes registers session management endpoints.
func registerSessionRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	protected.DELETE("/sessions/current", deps.authHandlers.Logout)
	protected.GET("/sessions/current", deps.authHandlers.GetCurrentUser)
}

// registerStationRoutes registers station CRUD endpoints.
func registerStationRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/stations", perm(auth.ResourceStations, auth.ActionRead), h.ListStations)
	protected.GET("/stations/:id", perm(auth.ResourceStations, auth.ActionRead), h.GetStation)
	protected.POST("/stations", perm(auth.ResourceStations, auth.ActionWrite), h.CreateStation)
	protected.PUT("/stations/:id", perm(auth.ResourceStations, auth.ActionWrite), h.UpdateStation)
	protected.DELETE("/stations/:id", perm(auth.ResourceStations, auth.ActionWrite), h.DeleteStation)
}

// registerVoiceRoutes registers voice CRUD endpoints.
func registerVoiceRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/voices", perm(auth.ResourceVoices, auth.ActionRead), h.ListVoices)
	protected.GET("/voices/:id", perm(auth.ResourceVoices, auth.ActionRead), h.GetVoice)
	protected.POST("/voices", perm(auth.ResourceVoices, auth.ActionWrite), h.CreateVoice)
	protected.PUT("/voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.UpdateVoice)
	protected.DELETE("/voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.DeleteVoice)
}

// registerStoryRoutes registers story CRUD and audio endpoints.
func registerStoryRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/stories", perm(auth.ResourceStories, auth.ActionRead), h.ListStories)
	protected.GET("/stories/:id", perm(auth.ResourceStories, auth.ActionRead), h.GetStory)
	protected.GET("/stories/:id/audio", perm(auth.ResourceStories, auth.ActionRead), func(c *gin.Context) {
		h.ServeAudio(c, handlers.AudioConfig{
			TableName:   "stories",
			IDColumn:    "id",
			FileColumn:  "audio_file",
			FilePrefix:  "story",
			ContentType: "audio/wav",
			Directory:   "processed",
		})
	})
	protected.POST("/stories/:id/audio", perm(auth.ResourceStories, auth.ActionWrite), h.UploadStoryAudio)
	protected.POST("/stories/:id/tts", perm(auth.ResourceStories, auth.ActionWrite), h.GenerateStoryTTS)
	protected.POST("/stories", perm(auth.ResourceStories, auth.ActionWrite), h.CreateStory)
	protected.PUT("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.UpdateStory)
	protected.DELETE("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.DeleteStory)
	protected.PATCH("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.UpdateStoryStatus)
}

// registerUserRoutes registers user management endpoints (admin only).
func registerUserRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/users", perm(auth.ResourceUsers, auth.ActionRead), h.ListUsers)
	protected.GET("/users/:id", perm(auth.ResourceUsers, auth.ActionRead), h.GetUser)
	protected.POST("/users", perm(auth.ResourceUsers, auth.ActionWrite), h.CreateUser)
	protected.PUT("/users/:id", perm(auth.ResourceUsers, auth.ActionWrite), h.UpdateUser)
	protected.DELETE("/users/:id", perm(auth.ResourceUsers, auth.ActionWrite), h.DeleteUser)
	protected.PATCH("/users/:id", perm(auth.ResourceUsers, auth.ActionWrite), h.UpdateUserStatus)
}

// registerStationVoiceRoutes registers station-voice relationship endpoints.
func registerStationVoiceRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/station-voices", perm(auth.ResourceVoices, auth.ActionRead), h.ListStationVoices)
	protected.GET("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionRead), h.GetStationVoice)
	protected.GET("/station-voices/:id/audio", perm(auth.ResourceVoices, auth.ActionRead), func(c *gin.Context) {
		h.ServeAudio(c, handlers.AudioConfig{
			TableName:   "station_voices",
			IDColumn:    "id",
			FileColumn:  "audio_file",
			FilePrefix:  "jingle",
			ContentType: "audio/wav",
			Directory:   "processed",
		})
	})
	protected.POST("/station-voices/:id/audio", perm(auth.ResourceVoices, auth.ActionWrite), h.UploadStationVoiceAudio)
	protected.POST("/station-voices", perm(auth.ResourceVoices, auth.ActionWrite), h.CreateStationVoice)
	protected.PUT("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.UpdateStationVoice)
	protected.DELETE("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.DeleteStationVoice)
}

// registerBulletinRoutes registers bulletin endpoints.
func registerBulletinRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/bulletins", perm(auth.ResourceBulletins, auth.ActionRead), h.ListBulletins)
	protected.GET("/bulletins/:id", perm(auth.ResourceBulletins, auth.ActionRead), h.GetBulletin)
	protected.POST("/stations/:id/bulletins", perm(auth.ResourceBulletins, auth.ActionGenerate), h.GenerateBulletin)
	protected.GET("/stations/:id/bulletins", perm(auth.ResourceBulletins, auth.ActionRead), h.GetStationBulletins)
	protected.GET("/bulletins/:id/audio", perm(auth.ResourceBulletins, auth.ActionRead), h.GetBulletinAudio)
	protected.GET("/stories/:id/bulletins", perm(auth.ResourceStories, auth.ActionRead), h.GetStoryBulletinHistory)
	protected.GET("/bulletins/:id/stories", perm(auth.ResourceStories, auth.ActionRead), h.GetBulletinStories)
}

// registerHealthRoute registers the health check endpoint.
func registerHealthRoute(r *gin.Engine) {
	r.GET("/health", func(c *gin.Context) {
		utils.Success(c, handlers.HealthResponse{
			Status:  "ok",
			Service: "babbel-api",
		})
	})
}

// securityHeaders adds OWASP-recommended security headers to all responses.
func securityHeaders(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Core security headers (always applied)
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		// HSTS header - only for production or HTTPS requests
		if cfg.Environment == "production" || c.Request.TLS != nil {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// corsMiddleware creates a CORS middleware for the configured allowed origins.
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
			c.Writer.Header().Set("Access-Control-Allow-Headers",
				"Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, "+
					"Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE, PATCH")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// isAllowedOrigin reports whether the origin is in the allowed origins list.
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

// getEnv retrieves an environment variable with fallback to a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
