package main

import (
	"central-auth/internal/http/middleware"
	"central-auth/internal/config"
	"central-auth/internal/http/handler"
	"central-auth/internal/repository"
	"central-auth/internal/service"
	"fmt"

	"github.com/gin-gonic/gin"
)

func main() {
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
	authHandler := handler.NewAuthHandler(authService)

	// Start server
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	auth := r.Group("/auth")
	auth.Use(middleware.ServiceAuthMiddleware())
	{
		auth.POST("/login", authHandler.Login)
		auth.POST("/oauth/login", authHandler.OAuthLogin)
	}

	r.Run(":8081")
}