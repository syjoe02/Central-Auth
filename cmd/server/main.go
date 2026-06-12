package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	authv1 "central-auth/gen/go/auth/v1"
	"central-auth/internal/blacklist"
	"central-auth/internal/config"
	"central-auth/internal/database"
	grpcinterceptor "central-auth/internal/grpc/interceptor"
	grpcserver "central-auth/internal/grpc/server"
	"central-auth/internal/http/handler"
	"central-auth/internal/http/middleware"
	hydraclient "central-auth/internal/hydra"
	"central-auth/internal/kafka"
	kratosclient "central-auth/internal/kratos"
	"central-auth/internal/metrics"
	"central-auth/internal/repository"
	"central-auth/internal/resilience"
	"central-auth/internal/service"
	"central-auth/internal/session"

	gocache "github.com/patrickmn/go-cache"

	"github.com/getsentry/sentry-go"
	sentrygin "github.com/getsentry/sentry-go/gin"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

func main() {
	// ── Default structured logger (service field propagated to all slog.* calls) ─
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(slog.String("service", "central-auth")))

	// ── Sentry (optional; disabled when SENTRY_DSN is empty) ────────────────
	if dsn := os.Getenv("SENTRY_DSN"); dsn != "" {
		if err := sentry.Init(sentry.ClientOptions{
			Dsn:              dsn,
			Environment:      os.Getenv("APP_ENV"),
			TracesSampleRate: 0.1,
			// AttachStacktrace: true causes sentry-go to capture a runtime stack trace
			// for every CaptureMessage and CaptureException call, including circuit-breaker
			// state-change callbacks.  This ensures level=error/fatal events always include
			// a full Go stack in the Sentry UI, not just a bare message string.
			AttachStacktrace: true,
			// ProfilesSampleRate: 0.1 — field does not exist in sentry-go v0.44.1.
			// TODO: Add ProfilesSampleRate: 0.1 when upgrading to a release that includes
			// the profiling integration in ClientOptions (target: 0.1 to limit overhead/PII).
		}); err != nil {
			log.Printf("[WARN] Sentry init failed: %v", err)
		} else {
			defer sentry.Flush(2 * time.Second)
			log.Println("[INFO] Sentry error tracking initialised")
		}
	}

	// ── Server config (fail-fast secret validation) ───────────────────────────
	serverConfig := config.LoadServerConfig()

	// ── Kafka access-log producer + device-session consumer ──────────────────
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

	// ── Database migrations ───────────────────────────────────────────────────
	if err := database.RunMigrations(config.PostgresDSN()); err != nil {
		log.Fatalf("[FATAL] database migration failed: %v", err)
	}
	log.Println("[INFO] Database migrations applied")

	// ── Resilience: circuit breaker + L1 cache ───────────────────────────────
	resilienceCfg := config.LoadResilienceConfig()
	cb := resilience.NewCircuitBreaker(resilience.ResilienceCBConfig{
		FailureThreshold: resilienceCfg.FailureThreshold,
		ProbeBaseNanos:   int64(resilienceCfg.ProbeBaseSeconds) * int64(time.Second),
		ProbeMaxNanos:    int64(resilienceCfg.ProbeMaxSeconds) * int64(time.Second),
		JitterPct:        int64(resilienceCfg.JitterPct),
	}, resilience.WithOnStateChange(func(from, to resilience.State) {
		sentry.WithScope(func(scope *sentry.Scope) {
			scope.SetTag("from_state", from.String())
			scope.SetTag("to_state", to.String())
			scope.SetTag("target", "redis")
			if to == resilience.StateOpen {
				// CLOSED → OPEN is a fatal infrastructure event.
				// CaptureException sends the error as an *exception* event in Sentry,
				// which (combined with AttachStacktrace: true) includes a full Go stack
				// trace so engineers can pinpoint the call site that tripped the breaker.
				scope.SetTag("alert_id", "REDIS_DOWN_CIRCUIT_OPEN")
				scope.SetLevel(sentry.LevelFatal)
				sentry.CaptureException(fmt.Errorf("redis circuit breaker: %s → %s", from, to))
			} else {
				// OPEN → HALF-OPEN or HALF-OPEN → CLOSED are informational.
				// CaptureMessage is sufficient; AttachStacktrace still adds a stack.
				scope.SetLevel(sentry.LevelWarning)
				sentry.CaptureMessage(fmt.Sprintf("circuit breaker: %s → %s", from, to))
			}
		})
	}))
	l1Cache := gocache.New(1*time.Minute, 2*time.Minute)

	// ── Repositories ─────────────────────────────────────────────────────────
	blacklistPgRepo := repository.NewPostgresBlacklistRepository(pgPool)

	rawRedisRepo := repository.NewRedisRepository(rdb)
	rawSessionStore := session.NewRedisStore(rdb, bffConfig.SessionTTL)
	rawBlacklist := blacklist.NewRedisBlacklist(rdb)

	resilientRedisRepo := resilience.NewResilientRedisRepo(rawRedisRepo, cb, l1Cache)
	resilientSessionStore := resilience.NewResilientSessionStore(rawSessionStore, cb, l1Cache)
	resilientBlacklist := resilience.NewResilientBlacklist(rawBlacklist, cb, l1Cache, blacklistPgRepo)
	idempotencyCache := resilience.NewResilientIdempotencyCache(rdb, cb)

	// Background blacklist sync — when the circuit is OPEN, periodically bulk-loads
	// all active blacklisted JTIs from PostgreSQL into the L1 cache.
	// This prevents a per-request PG lookup spike during Redis outages.
	// The sync context is cancelled during graceful shutdown (see shutdownDone below).
	bgSyncCtx, bgSyncCancel := context.WithCancel(context.Background())
	resilientBlacklist.StartBackgroundSync(bgSyncCtx, 1*time.Minute)
	log.Println("[INFO] Blacklist background sync started (interval: 1m)")

	// Instrumented wrapper sits outside the resilient layer so Prometheus latency
	// metrics reflect actual attempt counts (not CB fast-fails).
	redisRepo := repository.NewInstrumentedRedisRepo(resilientRedisRepo)
	deviceSessionRepo := repository.NewInstrumentedDeviceSessionRepository(
		repository.NewPostgresDeviceSessionRepository(pgPool),
	)
	globalBlacklistRepo := repository.NewPostgresGlobalBlacklistRepository(pgPool)

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

	// ── Device-session Kafka consumer (started after repo is ready) ──────────
	// Reads AuthSessionEvents from the access-logs topic and persists them to
	// device_sessions. Runs in its own goroutine; stopped before the producer
	// closes to ensure no in-flight DB writes are abandoned.
	// Only started when a real broker is reachable; skipped for NoopPublisher so
	// there is no reconnect log spam in non-production environments.
	var deviceSessionConsumer *kafka.DeviceSessionConsumer
	var consumerCancel context.CancelFunc = func() {} // no-op default

	if kafka.ShouldStartConsumer(kafkaProducer) {
		var consumerCtx context.Context
		consumerCtx, consumerCancel = context.WithCancel(context.Background())
		deviceSessionConsumer = kafka.NewDeviceSessionConsumer(kafkaConfig, deviceSessionRepo)
		go deviceSessionConsumer.Run(consumerCtx)
		log.Printf("[INFO] device-session Kafka consumer started")
	} else {
		log.Printf("[INFO] Kafka unavailable — device-session consumer skipped")
	}

	// ── S2S auth service (existing /auth/* endpoints) ─────────────────────────
	authService := service.NewInstrumentedAuthService(
		service.NewOryAuthService(
			hydraClient, redisRepo, deviceSessionRepo,
			service.WithKratosClient(kratosAdminClient),
			service.WithEventPublisher(kafkaProducer),
		),
	)

	// ── BFF session layer ─────────────────────────────────────────────────────
	bffService := service.NewBFFService(hydraClient, resilientSessionStore, resilientBlacklist, redisRepo, deviceSessionRepo, bffConfig, kafkaProducer)

	// ── Admin blacklist service ───────────────────────────────────────────────
	adminBlacklistSvc := service.NewAdminBlacklistService(globalBlacklistRepo, deviceSessionRepo, kafkaProducer)

	// ── Proxy config (Kotlin API gateway) ────────────────────────────────────
	proxyConfig, err := config.LoadProxyConfig()
	if err != nil {
		log.Fatalf("[FATAL] proxy config: %v", err)
	}
	proxyHandler, err := handler.NewProxyHandler(proxyConfig.KotlinURL, proxyConfig.DialTimeout, proxyConfig.KotlinServiceKey)
	if err != nil {
		log.Fatalf("[FATAL] proxy handler init: %v", err)
	}

	// ── Handlers ──────────────────────────────────────────────────────────────
	authHandler := handler.NewAuthHandler(authService)
	bffHandler := handler.NewBFFHandler(bffService, bffConfig)
	adminHandler := handler.NewAdminHandler(hydraClient)
	adminBlacklistHandler := handler.NewAdminBlacklistHandler(adminBlacklistSvc)

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
	r.Use(sentrygin.New(sentrygin.Options{Repanic: true}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.Use(middleware.KafkaAccessLogMiddleware(kafkaProducer))
	r.Use(middleware.PrometheusMiddleware())
	// CORS must be registered at the router level, not on individual groups.
	// Gin only runs group middleware when a route matches; OPTIONS preflights
	// never match a POST/GET route, so group-level CORS never fires for them.
	// A router-level middleware runs unconditionally and handles all preflights.
	r.Use(middleware.CORSMiddleware(corsOrigins))

	// ── S2S routes (service-to-service only, X-Service-Key required) ──────────
	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware(serverConfig.ServiceAPIKey))
	{
		auth.POST("/refresh", middleware.RateLimitMiddleware(), authHandler.Refresh)
		auth.POST("/logout", authHandler.Logout)
		auth.POST("/logout-all", authHandler.LogoutAll)
		auth.POST("/verify", authHandler.Verify)
		auth.POST("/google/login", authHandler.GoogleLogin)
	}

	// ── Browser-facing auth routes (no service key, rate-limited) ─────────────
	// Signup is browser-callable: no X-Service-Key required.
	pubAuth := r.Group("/auth")
	pubAuth.Use(middleware.RateLimitMiddleware())
	{
		pubAuth.POST("/signup", authHandler.Signup)
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
		protected.Use(middleware.CSRFMiddleware(bffConfig.CSRFSecret, bffConfig.CookieSecure))
		{
			protected.POST("/logout", bffHandler.Logout)
			protected.POST("/logout-all", bffHandler.LogoutAll)
			protected.GET("/whoami", bffHandler.WhoAmI)
		}
	}

	// ── Kotlin API proxy (/api/* → backendKotlin, JWT validated at the edge) ────────
	// Auth-free paths (/api/auth/*) are forwarded without token validation so
	// the backend can handle login/signup/refresh/logout natively.
	// All other /api/* paths require a valid Hydra access token. Browser callers
	// use the __session cookie (resolved to Bearer by BFFAPIBridgeMiddleware);
	// S2S callers supply Authorization: Bearer directly.
	api := r.Group("/api")
	api.Use(middleware.CORSMiddleware(corsOrigins))
	api.Use(middleware.RateLimitMiddleware())
	api.Use(middleware.BFFAPIBridgeMiddleware(bffService))
	api.Any("/*path", proxyHandler.Handle)

	// ── Admin routes (X-Service-Key protected) ────────────────────────────────
	admin := r.Group("/admin")
	admin.Use(middleware.ServiceAuthMiddleware(serverConfig.ServiceAPIKey))
	{
		admin.POST("/jwks/refresh", adminHandler.RefreshJWKS)
		admin.POST("/blacklist/block", adminBlacklistHandler.Block)
		admin.DELETE("/blacklist/block", adminBlacklistHandler.Unblock)
	}

	// ── gRPC server (9-stage interceptor chain) ──────────────────────────────
	// Interceptor order (outermost → innermost):
	//   Recovery → Prometheus → RequestID → Logging →
	//   ServiceAuth → KafkaAccessLog → RateLimit → RateLimitMethods → Idempotency
	//
	// RateLimitMethods applies tighter per-method limits on Logout and LogoutAll
	// because they are expensive (Redis pipeline + Hydra revocation) and must be
	// protected against bulk-revocation abuse independently of the global limit.
	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcinterceptor.Recovery(),
			grpcinterceptor.Prometheus(),
			grpcinterceptor.RequestID(),
			grpcinterceptor.Logging(),
			grpcinterceptor.ServiceAuth(serverConfig.ServiceAPIKey),
			grpcinterceptor.KafkaAccessLog(kafkaProducer),
			grpcinterceptor.RateLimit(serverConfig.RateLimitRequestsPerMin),
			grpcinterceptor.RateLimitMethods(map[string]int{
				"/auth.v1.AuthService/Logout":    10,
				"/auth.v1.AuthService/LogoutAll": 5,
			}),
			grpcinterceptor.Idempotency(idempotencyCache),
		),
	)
	authv1.RegisterAuthServiceServer(grpcSrv, grpcserver.New(authService))

	grpcLis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("[FATAL] gRPC listen :50051: %v", err)
	}
	go func() {
		log.Println("[INFO] gRPC server listening on :50051")
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Printf("[ERROR] gRPC server exited: %v", err)
		}
	}()

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

		// ── Phase 1: drain HTTP + gRPC servers (10 s shared budget) ─────────
		// H-3: all servers must be fully stopped before Kafka is closed.
		// Any in-flight handler that calls Publish must complete first;
		// only then is it safe to close the producer channel.
		httpCtx, httpCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer httpCancel()
		var httpWg sync.WaitGroup
		httpWg.Add(3)
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
		go func() {
			defer httpWg.Done()
			grpcSrv.GracefulStop() // waits for in-flight RPCs to complete
		}()
		httpWg.Wait() // H-3: no more Publish calls possible after this point

		// ── Phase 1.5: stop background goroutines ────────────────────────────
		bgSyncCancel()   // stop blacklist background sync
		consumerCancel() // stop device-session Kafka consumer
		if deviceSessionConsumer != nil {
			<-deviceSessionConsumer.RunDone()
			if err := deviceSessionConsumer.Close(); err != nil {
				log.Printf("[ERROR] Device-session consumer close: %v", err)
			}
		}

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
