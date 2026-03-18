package handler

import (
	"log"
	"net/http"

	"central-auth/internal/model"
	"central-auth/internal/token"

	"github.com/gin-gonic/gin"
)

func (h *AuthHandler) OAuthLogin(c *gin.Context) {
	var req model.OAuthLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Provider != "google" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported provider"})
		return
	}

	// 1. Check Google Token
	claims, err := token.VerifyGoogleIDToken(
		req.IdToken,
		h.googleClientID,
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid google token"})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	var uaPtr *string
	var ipPtr *string

	if userAgent != "" {
		uaPtr = &userAgent
	}
	if ip != "" {
		ipPtr = &ip
	}

	access, refresh, err := h.authService.OAuthLogin(
		c.Request.Context(),
		"google",
		claims.Subject,
		claims.Email,
		req.DeviceID,
		req.RememberMe,
		uaPtr,
		ipPtr,
	)
	if err != nil {
		log.Printf("OAuthLogin error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
	})
}
