package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (h *AuthHandler) Refresh(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
		return
	}

	refreshToken := parts[1]

	accessToken, newRefreshToken, err := h.authService.Refresh(refreshToken)
	if err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh_failed", "error_code": "server_error", "reason": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": newRefreshToken,
	})
}
