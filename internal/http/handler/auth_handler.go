package handler

import (
	"net/http"
	"strings"

	"central-auth/internal/model"
	"central-auth/internal/service"
	"central-auth/internal/token"

	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func bearerToken(c *gin.Context) (string, bool) {
	h := c.GetHeader("Authorization")
	if h == "" {
		return "", false
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", false
	}
	return parts[1], true
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.DeviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device_id is required"})
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

	access, refresh, err := h.authService.Login(
		req.UserID,
		req.DeviceID,
		req.RememberMe,
		uaPtr,
		ipPtr,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, model.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	accessToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.Logout(accessToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_failed", "reason": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"result": "logged_out"})
}

func (h *AuthHandler) LogoutAll(c *gin.Context) {
	accessToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.LogoutAll(accessToken); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_all_failed", "reason": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "logged_out_all"})
}

func (h *AuthHandler) Verify(c *gin.Context) {
	tokenStr, ok := bearerToken(c)
	if !ok {
		c.JSON(401, gin.H{"error": "missing token"})
		return
	}

	claims, err := token.Parse(tokenStr)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid token"})
		return
	}

	// Redis에 refresh token이 살아있는지 확인 (세션 존재 확인)
	exists, err := h.authService.ExistsSession(
		claims.UserID,
		claims.DeviceID,
	)
	if err != nil || !exists {
		c.JSON(401, gin.H{"error": "session expired"})
		return
	}

	c.JSON(200, gin.H{
		"user_id":   claims.UserID,
		"device_id": claims.DeviceID,
		"exp":       claims.ExpiresAt.Time.Unix(),
	})
}
