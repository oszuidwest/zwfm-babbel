// Package api provides HTTP routing and middleware setup for the Babbel API server.
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/api/handlers"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/notify"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/scheduler"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/tts"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/gorm"
)

type routerDeps struct {
	handlers          *handlers.Handlers
	automationHandler *handlers.AutomationHandler
	authHandlers      *AuthHandlers
	authService       *auth.Service
	bulletinJobSvc    *services.BulletinJobService
}

// SetupRouter configures routes and returns a bulletin worker for the caller to start.
// alerts must be non-nil.
func SetupRouter(
	db *gorm.DB,
	cfg *config.Config,
	alerts *notify.Service,
) (*gin.Engine, *services.BulletinJobService, error) {
	deps, err := buildDependencies(db, cfg, alerts)
	if err != nil {
		return nil, nil, err
	}

	if cfg.Environment.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	utils.InitializeValidators()

	r := setupEngine(cfg, deps.authService, alerts)
	registerPublicRoutes(r, deps)
	registerAPIRoutes(r, deps)
	registerHealthRoute(r, db, alerts)

	return r, deps.bulletinJobSvc, nil
}

func buildDependencies(db *gorm.DB, cfg *config.Config, alerts notify.Alerter) (*routerDeps, error) {
	txManager := repository.NewTxManager(db)

	stationRepo := repository.NewStationRepository(db)
	voiceRepo := repository.NewVoiceRepository(db)
	userRepo := repository.NewUserRepository(db)
	storyRepo := repository.NewStoryRepository(db)
	bulletinRepo := repository.NewBulletinRepository(db)
	bulletinJobRepo := repository.NewBulletinJobRepository(db)
	stationVoiceRepo := repository.NewStationVoiceRepository(db)
	audioRepo := repository.NewAudioRepository(db)
	ttsSettingsRepo := repository.NewTTSSettingsRepository(db)
	pronunciationRuleRepo := repository.NewPronunciationRuleRepository(db)

	audioSvc := audio.NewService(cfg, alerts)
	ttsSvc := tts.NewService(&cfg.TTS)
	ttsSettingsSvc := services.NewTTSSettingsService(ttsSettingsRepo)
	pronunciationInjector := services.NewPronunciationInjector(pronunciationRuleRepo)
	pronunciationRulesSvc := services.NewPronunciationRulesService(pronunciationRuleRepo, txManager)

	bulletinSvc := services.NewBulletinService(services.BulletinServiceDeps{
		TxManager:    txManager,
		BulletinRepo: bulletinRepo,
		StationRepo:  stationRepo,
		StoryRepo:    storyRepo,
		AudioSvc:     audioSvc,
		Config:       cfg,
		Alerts:       alerts,
	})
	bulletinJobSvc := services.NewBulletinJobService(
		bulletinJobRepo,
		bulletinSvc,
		cfg.BulletinJobs,
		alerts,
	)
	storySvc := services.NewStoryService(services.StoryServiceDeps{
		StoryRepo:             storyRepo,
		VoiceRepo:             voiceRepo,
		AudioSvc:              audioSvc,
		TTSSvc:                ttsSvc,
		TTSSettingsSvc:        ttsSettingsSvc,
		PronunciationInjector: pronunciationInjector,
		Config:                cfg,
		Alerts:                alerts,
	})
	stationSvc := services.NewStationService(stationRepo)
	voiceSvc := services.NewVoiceService(voiceRepo)
	userSvc := services.NewUserService(userRepo, buildPasswordPolicy(cfg))
	stationVoiceSvc := services.NewStationVoiceService(services.StationVoiceServiceDeps{
		TxManager:        txManager,
		StationVoiceRepo: stationVoiceRepo,
		StationRepo:      stationRepo,
		VoiceRepo:        voiceRepo,
		AudioSvc:         audioSvc,
		Config:           cfg,
	})

	h := handlers.NewHandlers(handlers.HandlersDeps{
		AudioRepo:             audioRepo,
		AudioSvc:              audioSvc,
		Config:                cfg,
		BulletinSvc:           bulletinSvc,
		BulletinJobSvc:        bulletinJobSvc,
		StorySvc:              storySvc,
		StationSvc:            stationSvc,
		VoiceSvc:              voiceSvc,
		UserSvc:               userSvc,
		StationVoiceSvc:       stationVoiceSvc,
		TTSSettingsSvc:        ttsSettingsSvc,
		PronunciationRulesSvc: pronunciationRulesSvc,
		TTSEnabled:            ttsSvc != nil,
	})
	automationHandler := handlers.NewAutomationHandler(bulletinSvc, stationSvc, cfg, alerts)

	authService, err := auth.NewService(buildAuthConfig(cfg), db, alerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth service: %w", err)
	}
	return &routerDeps{
		handlers:          h,
		automationHandler: automationHandler,
		authHandlers:      NewAuthHandlers(authService, cfg.FrontendURL, h),
		authService:       authService,
		bulletinJobSvc:    bulletinJobSvc,
	}, nil
}

func buildPasswordPolicy(cfg *config.Config) services.PasswordPolicy {
	return services.PasswordPolicy{
		MinLength:          cfg.Auth.Local.MinPasswordLength,
		RequireUppercase:   cfg.Auth.Local.RequireUppercase,
		RequireLowercase:   cfg.Auth.Local.RequireLowercase,
		RequireNumber:      cfg.Auth.Local.RequireNumber,
		RequireSpecialChar: cfg.Auth.Local.RequireSpecialChar,
	}
}

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
			MaxFailedAttempts:      cfg.Auth.Local.MaxLoginAttempts,
			LockoutDurationMinutes: cfg.Auth.Local.LockoutDurationMinutes,
		},
		Session: auth.SessionConfig{
			MaxAge:         86400,
			CookieName:     "babbel_session",
			CookiePath:     "/",
			CookieDomain:   cfg.Auth.CookieDomain,
			CookieSecure:   cfg.Environment.IsProduction(),
			CookieHTTPOnly: true,
			CookieSameSite: string(cfg.Auth.CookieSameSite),
			SecretKey:      cfg.Auth.SessionSecret,
		},
		AllowedOrigins: cfg.Server.AllowedOrigins,
	}
}

func setupEngine(cfg *config.Config, authService *auth.Service, alerts *notify.Service) *gin.Engine {
	r := gin.New()
	// Query strings may contain automation API keys.
	r.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		SkipQueryString: true,
	}))
	r.Use(gin.Recovery())
	// Skip alert tracking when e-mail is unavailable.
	if alerts.IsConfigured() {
		r.Use(handlers.NotificationMiddleware(alerts))
	}
	r.Use(authService.SessionMiddleware())
	// CORS may abort preflight requests, so set security headers first.
	r.Use(securityHeaders(cfg))
	r.Use(corsMiddleware(cfg))
	return r
}

func registerPublicRoutes(r *gin.Engine, deps *routerDeps) {
	public := r.Group("/public")
	public.GET("/stations/:id/bulletin.wav", deps.automationHandler.GetPublicBulletin)
}

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
	registerTTSSettingsRoutes(protected, deps)
	registerPronunciationRulesRoutes(protected, deps)
}

func registerAuthRoutes(v1 *gin.RouterGroup, deps *routerDeps) {
	v1.GET("/auth/config", deps.authHandlers.GetAuthConfig)
	v1.POST("/sessions", deps.authHandlers.Login)
	v1.GET("/auth/oauth", deps.authHandlers.StartOAuthFlow)
	v1.GET("/auth/oauth/callback", deps.authHandlers.HandleOAuthCallback)
}

func registerSessionRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	protected.DELETE("/sessions/current", deps.authHandlers.Logout)
	protected.GET("/sessions/current", deps.authHandlers.GetCurrentUser)
}

func registerStationRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/stations", perm(auth.ResourceStations, auth.ActionRead), h.ListStations)
	protected.GET("/stations/:id", perm(auth.ResourceStations, auth.ActionRead), h.GetStation)
	protected.POST("/stations", perm(auth.ResourceStations, auth.ActionWrite), h.CreateStation)
	protected.PUT("/stations/:id", perm(auth.ResourceStations, auth.ActionWrite), h.UpdateStation)
	protected.DELETE("/stations/:id", perm(auth.ResourceStations, auth.ActionWrite), h.DeleteStation)
}

func registerVoiceRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/voices", perm(auth.ResourceVoices, auth.ActionRead), h.ListVoices)
	protected.GET("/voices/:id", perm(auth.ResourceVoices, auth.ActionRead), h.GetVoice)
	protected.POST("/voices", perm(auth.ResourceVoices, auth.ActionWrite), h.CreateVoice)
	protected.PUT("/voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.UpdateVoice)
	protected.DELETE("/voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.DeleteVoice)
}

func registerStoryRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/stories", perm(auth.ResourceStories, auth.ActionRead), h.ListStories)
	protected.GET("/stories/:id", perm(auth.ResourceStories, auth.ActionRead), h.GetStory)
	protected.GET("/stories/:id/audio", perm(auth.ResourceStories, auth.ActionRead), func(c *gin.Context) {
		h.ServeAudio(c, handlers.AudioConfig{
			TableName:  "stories",
			FilePrefix: "story",
		})
	})
	protected.POST("/stories/:id/audio", perm(auth.ResourceStories, auth.ActionWrite), extendUploadReadDeadline, h.UploadStoryAudio)
	protected.POST("/stories/:id/tts", perm(auth.ResourceStories, auth.ActionWrite), h.GenerateStoryTTS)
	protected.POST("/stories", perm(auth.ResourceStories, auth.ActionWrite), h.CreateStory)
	protected.PUT("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.UpdateStory)
	protected.DELETE("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.DeleteStory)
	protected.PATCH("/stories/:id", perm(auth.ResourceStories, auth.ActionWrite), h.UpdateStoryStatus)
}

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

func registerStationVoiceRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/station-voices", perm(auth.ResourceVoices, auth.ActionRead), h.ListStationVoices)
	protected.GET("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionRead), h.GetStationVoice)
	protected.GET("/station-voices/:id/audio", perm(auth.ResourceVoices, auth.ActionRead), func(c *gin.Context) {
		h.ServeAudio(c, handlers.AudioConfig{
			TableName:  "station_voices",
			FilePrefix: "jingle",
		})
	})
	protected.POST("/station-voices/:id/audio", perm(auth.ResourceVoices, auth.ActionWrite), extendUploadReadDeadline, h.UploadStationVoiceAudio)
	protected.POST("/station-voices", perm(auth.ResourceVoices, auth.ActionWrite), h.CreateStationVoice)
	protected.PUT("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.UpdateStationVoice)
	protected.DELETE("/station-voices/:id", perm(auth.ResourceVoices, auth.ActionWrite), h.DeleteStationVoice)
}

func registerBulletinRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/bulletins", perm(auth.ResourceBulletins, auth.ActionRead), h.ListBulletins)
	protected.GET("/bulletin-jobs/:id", perm(auth.ResourceBulletins, auth.ActionRead), h.GetBulletinJob)
	protected.GET("/bulletins/:id", perm(auth.ResourceBulletins, auth.ActionRead), h.GetBulletin)
	protected.POST("/stations/:id/bulletins", perm(auth.ResourceBulletins, auth.ActionGenerate), h.GenerateBulletin)
	protected.GET("/stations/:id/bulletins", perm(auth.ResourceBulletins, auth.ActionRead), h.GetStationBulletins)
	protected.GET("/stations/:id/bulletins/latest", perm(auth.ResourceBulletins, auth.ActionRead), h.GetLatestStationBulletin)
	protected.GET("/bulletins/:id/audio", perm(auth.ResourceBulletins, auth.ActionRead), h.GetBulletinAudio)
	protected.GET("/stories/:id/bulletins", perm(auth.ResourceStories, auth.ActionRead), h.GetStoryBulletinHistory)
	protected.GET("/bulletins/:id/stories", perm(auth.ResourceStories, auth.ActionRead), h.GetBulletinStories)
}

func registerTTSSettingsRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET("/settings/tts", perm(auth.ResourceSettingsTTS, auth.ActionRead), h.GetTTSSettings)
	protected.PATCH("/settings/tts", perm(auth.ResourceSettingsTTS, auth.ActionWrite), h.UpdateTTSSettings)
}

func registerPronunciationRulesRoutes(protected *gin.RouterGroup, deps *routerDeps) {
	h := deps.handlers
	perm := deps.authService.RequirePermission

	protected.GET(
		"/settings/tts/pronunciations",
		perm(auth.ResourcePronunciationRules, auth.ActionRead),
		h.GetPronunciationRules,
	)
	protected.PUT(
		"/settings/tts/pronunciations",
		perm(auth.ResourcePronunciationRules, auth.ActionWrite),
		h.UpdatePronunciationRules,
	)
}

// registerHealthRoute shares database checks and alerts with the background health service.
func registerHealthRoute(r *gin.Engine, db *gorm.DB, alerts notify.Alerter) {
	r.GET("/health", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := scheduler.CheckDatabase(ctx, db, alerts); err != nil {
			utils.ProblemExtended(
				c,
				http.StatusServiceUnavailable,
				"The health check could not connect to the database",
				"health.database_unavailable",
				"Restore the database connection and retry the health check",
			)
			return
		}
		utils.Success(c, handlers.HealthResponse{
			Status:  "ok",
			Service: "babbel-api",
		})
	})
}

func securityHeaders(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		if cfg.Environment.IsProduction() || c.Request.TLS != nil {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

func corsMiddleware(cfg *config.Config) gin.HandlerFunc {
	originChecker := config.NewOriginChecker(cfg.Server.AllowedOrigins)

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// An empty allowlist disables cross-origin access.
		if cfg.Server.AllowedOrigins == "" {
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
			c.Next()
			return
		}

		if originChecker.Allowed(origin) {
			// The configured allowlist takes precedence over proxy CORS headers.
			c.Writer.Header().Del("Access-Control-Allow-Origin")
			c.Writer.Header().Del("Access-Control-Allow-Credentials")
			c.Writer.Header().Del("Access-Control-Allow-Headers")
			c.Writer.Header().Del("Access-Control-Allow-Methods")

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
