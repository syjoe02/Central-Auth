package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"central-auth/internal/blacklist"
	"central-auth/internal/config"
	hydraclient "central-auth/internal/hydra"
	"central-auth/internal/http/handler"
	"central-auth/internal/http/middleware"
	_ "central-auth/internal/metrics"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"central-auth/internal/session"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// ── Required secrets / config ────────────────────────────────────────────
	if os.Getenv("SERVICE_API_KEY") == "" {
		panic("SERVICE_API_KEY env var must be set")
	}

	// ── Ory configuration ────────────────────────────────────────────────────
	oryConfig := config.LoadOryConfig()

	// ── BFF configuration ────────────────────────────────────────────────────
	bffConfig := config.LoadBFFConfig()

	// ── Redis ────────────────────────────────────────────────────────────────
	rdb := config.NewRedisClient()
	if _, err := rdb.Ping(config.Ctx).Result(); err != nil {
		panic(fmt.Sprintf("Redis ping failed: %v", err))
	}
	fmt.Println("Redis connected")

	// ── Postgres ─────────────────────────────────────────────────────────────
	pgPool, err := config.NewPostgresConn()
	if err != nil {
		panic(fmt.Sprintf("Postgres connect failed: %v", err))
	}
	defer pgPool.Close()
	fmt.Println("Postgres connected")

	// ── Repositories ─────────────────────────────────────────────────────────
	redisRepo := repository.NewInstrumentedRedisRepo(
		repository.NewRedisRepository(rdb),
	)
	deviceSessionRepo := repository.NewInstrumentedDeviceSessionRepository(
		repository.NewPostgresDeviceSessionRepository(pgPool),
	)

	// ── Ory clients ──────────────────────────────────────────────────────────
	hydraClient := hydraclient.New(
		oryConfig.HydraPublicURL,
		oryConfig.HydraAdminURL,
		oryConfig.HydraClientID,
		oryConfig.HydraClientSecret,
		oryConfig.HydraRedirectURI,
		hydraclient.WithGracePeriod(bffConfig.JWKSGracePeriod),
		// Validate iss and aud on every JWT so tokens from other Hydra instances
		// or clients are rejected even when a key matches. (Security finding F-1)
		hydraclient.WithExpectedIssuer(oryConfig.HydraPublicURL+"/"),
		hydraclient.WithExpectedAudience(oryConfig.HydraClientID),
	)

	// ── S2S auth service (existing /auth/* endpoints) ─────────────────────────
	authService := service.NewInstrumentedAuthService(
		service.NewOryAuthService(hydraClient, redisRepo, deviceSessionRepo),
	)

	// ── BFF session layer ─────────────────────────────────────────────────────
	sessionStore := session.NewRedisStore(rdb, bffConfig.SessionTTL)
	bl := blacklist.NewRedisBlacklist(rdb)
	bffService := service.NewBFFService(hydraClient, sessionStore, bl, redisRepo, deviceSessionRepo, bffConfig)

	// ── Handlers ──────────────────────────────────────────────────────────────
	authHandler := handler.NewAuthHandler(authService)
	bffHandler := handler.NewBFFHandler(bffService, bffConfig)
	adminHandler := handler.NewAdminHandler(hydraClient)

	// ── Router ───────────────────────────────────────────────────────────────
	r := gin.Default()
	r.Use(gin.LoggerWithWriter(os.Stdout))
	r.Use(gin.RecoveryWithWriter(os.Stderr))

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.Use(middleware.PrometheusMiddleware())

	// ── S2S routes (existing Django integration, unchanged) ───────────────────
	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware())
	{
		auth.POST("/login", middleware.RateLimitMiddleware(), authHandler.Login)
		auth.POST("/refresh", middleware.RateLimitMiddleware(), authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/logout-all", authHandler.LogoutAll)
		auth.POST("/verify", authHandler.Verify)
	}

	// ── BFF routes (browser cookie-based) ─────────────────────────────────────
	bff := r.Group("/bff")
	{
		// Login has no session middleware (creates the session).
		bff.POST("/login", middleware.RateLimitMiddleware(), bffHandler.Login)

		// All other BFF routes require a valid __session cookie + CSRF token.
		protected := bff.Group("")
		protected.Use(middleware.BFFSessionMiddleware())
		protected.Use(middleware.CSRFMiddleware(bffConfig.CSRFSecret))
		{
			protected.POST("/logout", bffHandler.Logout)
			protected.POST("/logout-all", bffHandler.LogoutAll)
			protected.GET("/whoami", bffHandler.WhoAmI)
		}
	}

	// ── Admin routes (X-Service-Key protected) ────────────────────────────────
	admin := r.Group("/admin")
	admin.Use(middleware.ServiceAuthMiddleware())
	{
		admin.POST("/jwks/refresh", adminHandler.RefreshJWKS)
	}

	// ── SIGHUP: zero-downtime JWKS key rotation trigger ───────────────────────
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGHUP)
		for range sigs {
			log.Println("[INFO] SIGHUP received: forcing JWKS cache refresh")
			if err := hydraClient.ForceRefreshJWKS(context.Background()); err != nil {
				log.Printf("[ERROR] JWKS force refresh failed: %v", err)
			} else {
				log.Println("[INFO] JWKS cache refreshed successfully")
			}
		}
	}()

	fmt.Println("Central-Auth server running on :8081 (BFF + Ory Kratos/Hydra backend)")
	if err := r.Run(":8081"); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
