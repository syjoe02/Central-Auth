package handler

import (
	"central-auth/internal/model"
	"central-auth/internal/token"
	"net/http"
	"os"

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
		os.Getenv("GOOGLE_CLIENT_ID"),
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
		"google",
		claims.Subject,
		claims.Email,
		req.DeviceID,
		req.RememberMe,
		uaPtr,
		ipPtr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  access,
		"refresh_token": refresh,
	})
}
