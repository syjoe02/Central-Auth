package main

import (
	"fmt"
	"log"
	"os"

	"central-auth/internal/config"
	hydraclient "central-auth/internal/hydra"
	"central-auth/internal/http/handler"
	"central-auth/internal/http/middleware"
	_ "central-auth/internal/metrics"
	"central-auth/internal/repository"
	"central-auth/internal/service"

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
	)

	// ── Service ──────────────────────────────────────────────────────────────
	authService := service.NewInstrumentedAuthService(
		service.NewOryAuthService(hydraClient, redisRepo, deviceSessionRepo),
	)

	// ── Handler ──────────────────────────────────────────────────────────────
	authHandler := handler.NewAuthHandler(authService)

	// ── Router ───────────────────────────────────────────────────────────────
	r := gin.Default()
	r.Use(gin.LoggerWithWriter(os.Stdout))
	r.Use(gin.RecoveryWithWriter(os.Stderr))

	r.GET("/metrics", gin.WrapH(promhttp.Handler()))
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.Use(middleware.PrometheusMiddleware())

	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware())
	{
		auth.POST("/login", middleware.RateLimitMiddleware(), authHandler.Login)
		auth.POST("/refresh", middleware.RateLimitMiddleware(), authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/logout-all", authHandler.LogoutAll)
		auth.POST("/verify", authHandler.Verify)
	}

	fmt.Println("Central-Auth server running on :8081 (Ory Kratos + Hydra backend)")
	if err := r.Run(":8081"); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
