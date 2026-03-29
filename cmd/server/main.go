package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"central-auth/internal/blacklist"
	"central-auth/internal/config"
	"central-auth/internal/http/handler"
	"central-auth/internal/http/middleware"
	hydraclient "central-auth/internal/hydra"
	"central-auth/internal/kafka"
	kratosclient "central-auth/internal/kratos"
	"central-auth/internal/metrics"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"central-auth/internal/session"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	// ── Server config (fail-fast secret validation) ───────────────────────────
	serverConfig := config.LoadServerConfig()

	// ── Kafka access-log producer ─────────────────────────────────────────────
	kafkaConfig := config.LoadKafkaConfig()
	kafkaProducer, kafkaErr := kafka.NewProducer(kafkaConfig)
	if kafkaErr != nil && kafkaConfig.IsProduction {
		log.Fatalf("[FATAL] Kafka broker unreachable in production: %v", kafkaErr)
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
	metrics.RegisterPGXStats("central_auth", pgPool)
	fmt.Println("Postgres and PGX metrics connected")

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
		hydraclient.WithExpectedAudience(oryConfig.HydraJWTAudience),
	)

	// ── Kratos admin client (identity management) ─────────────────────────────
	kratosAdminClient := kratosclient.New(oryConfig.KratosAdminURL, oryConfig.KratosPublicURL)

	// ── S2S auth service (existing /auth/* endpoints) ─────────────────────────
	authService := service.NewInstrumentedAuthService(
		service.NewOryAuthService(
			hydraClient, redisRepo, deviceSessionRepo,
			service.WithKratosClient(kratosAdminClient),
		),
	)

	// ── BFF session layer ─────────────────────────────────────────────────────
	sessionStore := session.NewRedisStore(rdb, bffConfig.SessionTTL)
	bl := blacklist.NewRedisBlacklist(rdb)
	bffService := service.NewBFFService(hydraClient, sessionStore, bl, redisRepo, deviceSessionRepo, bffConfig)

	// ── Proxy config (Django API gateway) ────────────────────────────────────
	proxyConfig, err := config.LoadProxyConfig()
	if err != nil {
		log.Fatalf("[FATAL] proxy config: %v", err)
	}
	proxyHandler, err := handler.NewProxyHandler(proxyConfig.DjangoURL, proxyConfig.DialTimeout, hydraClient)
	if err != nil {
		log.Fatalf("[FATAL] proxy handler init: %v", err)
	}

	// ── Handlers ──────────────────────────────────────────────────────────────
	authHandler := handler.NewAuthHandler(authService)
	bffHandler := handler.NewBFFHandler(bffService, bffConfig)
	adminHandler := handler.NewAdminHandler(hydraClient)

	// ── CORS origins (fail-fast in production if unset/wildcard) ─────────────
	corsOrigins := middleware.LoadCORSOrigins(serverConfig.AppEnv)

	// ── Router ───────────────────────────────────────────────────────────────
	r := gin.New()
	// Restrict trusted-proxy CIDR so c.ClientIP() cannot be spoofed via a
	// forged X-Forwarded-For header from untrusted callers. Adjust the CIDR
	// to match the actual upstream proxy / Docker network subnet.
	if err := r.SetTrustedProxies(serverConfig.TrustedProxyCIDRs); err != nil {
		log.Fatalf("[FATAL] invalid trusted proxy config: %v", err)
	}
	r.Use(gin.LoggerWithWriter(os.Stdout))
	r.Use(gin.RecoveryWithWriter(os.Stderr))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.Use(middleware.KafkaAccessLogMiddleware(kafkaProducer))
	r.Use(middleware.PrometheusMiddleware())

	// ── S2S routes (existing Django integration, unchanged) ───────────────────
	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware(serverConfig.ServiceAPIKey))
	{
		auth.POST("/signup", authHandler.Signup) // no rate limit — protected by X-Service-Key
		auth.POST("/login", middleware.RateLimitMiddleware(), authHandler.Login)
		auth.POST("/refresh", middleware.RateLimitMiddleware(), authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/logout-all", authHandler.LogoutAll)
		auth.POST("/verify", authHandler.Verify)
	}

	// ── BFF routes (browser cookie-based) ─────────────────────────────────────
	bff := r.Group("/bff")
	bff.Use(middleware.CORSMiddleware(corsOrigins))
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

	// ── Django API proxy (/api/* → Django, JWT validated at the edge) ────────
	// Auth-free paths (/api/auth/*) are forwarded without token validation so
	// Django can handle login/signup/refresh/logout natively.
	// All other /api/* paths require a valid Hydra access token (read from the
	// Authorization: Bearer header or the access_token httpOnly cookie).
	api := r.Group("/api")
	api.Use(middleware.CORSMiddleware(corsOrigins))
	api.Use(middleware.RateLimitMiddleware())
	api.Any("/*path", proxyHandler.Handle)

	// ── Admin routes (X-Service-Key protected) ────────────────────────────────
	admin := r.Group("/admin")
	admin.Use(middleware.ServiceAuthMiddleware(serverConfig.ServiceAPIKey))
	{
		admin.POST("/jwks/refresh", adminHandler.RefreshJWKS)
	}

	// ── Metrics server (internal only, not published to host) ─────────────────
	// MetricsAllowlistHandler checks RemoteAddr (direct TCP peer). There is no
	// proxy in front of :9091; if one is ever added the CIDR must cover the
	// proxy subnet, not the originating scraper address.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsSrv := &http.Server{Addr: ":9091", Handler: middleware.MetricsAllowlistHandler(serverConfig.MetricsBasicAuthUser, serverConfig.MetricsBasicAuthPassword, metricsMux)}
	metricsErr := make(chan error, 1)
	go func() {
		log.Println("[INFO] Metrics server listening on :9091 (internal only)")
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			metricsErr <- err
		}
	}()

	// ── SIGHUP: zero-downtime JWKS key rotation trigger ───────────────────────
	// M-3: sighupStop lets the shutdown goroutine unblock the SIGHUP loop so
	// the goroutine exits cleanly rather than leaking at process end.
	sighupStop := make(chan struct{})
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGHUP)
		defer signal.Stop(sigs) // M-3: deregister on exit so the channel can be GC'd
		for {
			select {
			case <-sigs:
				log.Println("[INFO] SIGHUP received: forcing JWKS cache refresh")
				if err := hydraClient.ForceRefreshJWKS(context.Background()); err != nil {
					log.Printf("[ERROR] JWKS force refresh failed: %v", err)
				} else {
					log.Println("[INFO] JWKS cache refreshed successfully")
				}
			case <-sighupStop:
				return
			}
		}
	}()

	// ── Graceful shutdown on SIGTERM / SIGINT ─────────────────────────────────
	// M-5: shutdownDone lets main block until the full two-phase drain completes,
	// preventing the process from exiting while goroutines are still flushing.
	mainSrv := &http.Server{Addr: ":8081", Handler: r}
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone) // M-5: signal main when fully drained
		select {
		case <-quit:
			log.Println("[INFO] Shutdown signal received")
		case err := <-metricsErr:
			log.Printf("[ERROR] Metrics server failed: %v", err)
		}

		// Stop SIGHUP handler before draining so no concurrent JWKS refresh
		// races with shutdown. (M-3)
		close(sighupStop)

		// ── Phase 1: drain HTTP servers (10 s shared budget) ──────────────────
		// H-3: HTTP servers must be fully stopped before Kafka is closed.
		// Any in-flight handler that calls Publish must complete first;
		// only then is it safe to close the producer channel.
		httpCtx, httpCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpCancel()
		var httpWg sync.WaitGroup
		httpWg.Add(2)
		go func() {
			defer httpWg.Done()
			if err := mainSrv.Shutdown(httpCtx); err != nil {
				log.Printf("[ERROR] Main server shutdown: %v", err)
			}
		}()
		go func() {
			defer httpWg.Done()
			if err := metricsSrv.Shutdown(httpCtx); err != nil {
				log.Printf("[ERROR] Metrics server shutdown: %v", err)
			}
		}()
		httpWg.Wait() // H-3: no more Publish calls possible after this point

		// ── Phase 2: drain Kafka producer (own 5 s budget) ────────────────────
		// M-4: Kafka gets a fresh context so its drain time is not charged
		// against the already-running HTTP deadline.
		kafkaCtx, kafkaCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer kafkaCancel()
		if err := kafkaProducer.Close(kafkaCtx); err != nil {
			log.Printf("[ERROR] Kafka producer close: %v", err)
		}
	}()

	fmt.Println("Central-Auth server running on :8081 (BFF + Ory Kratos/Hydra backend)")
	if err := mainSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server exited: %v", err)
	}
	<-shutdownDone // M-5: block until two-phase drain completes before process exits
}
