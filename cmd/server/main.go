package main

import (
	"fmt"
	"log"
	"os"

	"central-auth/internal/config"
	"central-auth/internal/http/handler"
	"central-auth/internal/http/middleware"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"central-auth/internal/token"

	"github.com/gin-gonic/gin"
)

func main() {
	// Secrets — panic immediately if required env vars are missing
	token.InitSecret()
	if os.Getenv("SERVICE_API_KEY") == "" {
		panic("SERVICE_API_KEY env var must be set")
	}
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")

	// Redis
	rdb := config.NewRedisClient()
	if _, err := rdb.Ping(config.Ctx).Result(); err != nil {
		panic(err)
	}
	fmt.Println("Redis connected")

	//Postgres
	pgPool, err := config.NewPostgresConn()
	if err != nil {
		panic(err)
	}
	defer pgPool.Close()
	fmt.Println("Postgres connected")

	// repo
	redisRepo := repository.NewRedisRepository(rdb)
	authUserRepo := repository.NewPostgresAuthUserRepository(pgPool)
	// Service
	authService := service.NewAuthService(redisRepo, authUserRepo)
	// Handler
	authHandler := handler.NewAuthHandler(authService, googleClientID)

	// Start server
	r := gin.Default()
	// log
	r.Use(gin.LoggerWithWriter(os.Stdout))
	r.Use(gin.RecoveryWithWriter(os.Stderr))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware())
	{
		auth.POST("/login", middleware.RateLimitMiddleware(), authHandler.Login)
		auth.POST("/oauth/login", middleware.RateLimitMiddleware(), authHandler.OAuthLogin)
		auth.POST("/refresh", middleware.RateLimitMiddleware(), authHandler.Refresh)

		auth.POST("/logout", authHandler.Logout)
		auth.POST("/logout-all", authHandler.LogoutAll)
		auth.POST("/verify", authHandler.Verify)
	}
	fmt.Println("Central-Auth server running on :8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
