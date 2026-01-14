package main

import (
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
	_, err := rdb.Ping(config.Ctx).Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("Redis connected")

	redisRepo := repository.NewRedisRepository(rdb)
	authService := service.NewAuthService(redisRepo)
	authHandler := handler.NewAuthHandler(authService)

	// Start server
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/login", authHandler.Login)
	}

	r.Run(":8081")
}