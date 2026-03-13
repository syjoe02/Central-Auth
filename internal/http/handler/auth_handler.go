package handler

import (
	"errors"
	"net/http"
	"strings"

	"central-auth/internal/model"
	"central-auth/internal/service"
	"central-auth/internal/token"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

// isTokenError returns true for errors caused by the caller (bad/expired/wrong-type token).
// Returns false for infrastructure failures (Redis, Postgres) which should be 500.
func isTokenError(err error) bool {
	return errors.Is(err, token.ErrWrongTokenType) ||
		errors.Is(err, jwt.ErrTokenMalformed) ||
		errors.Is(err, jwt.ErrTokenSignatureInvalid) ||
		errors.Is(err, jwt.ErrTokenUnverifiable) ||
		errors.Is(err, jwt.ErrTokenExpired) ||
		errors.Is(err, jwt.ErrTokenNotValidYet) ||
		errors.Is(err, jwt.ErrTokenInvalidClaims)
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
	refreshToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.Logout(refreshToken); err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout_failed", "error_code": "server_error", "reason": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "logged_out"})
}

func (h *AuthHandler) LogoutAll(c *gin.Context) {
	refreshToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.LogoutAll(refreshToken); err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_all_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout_all_failed", "error_code": "server_error", "reason": err.Error()})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "logged_out_all"})
}

func (h *AuthHandler) Verify(c *gin.Context) {
	tokenStr, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	// ParseTyped enforces token_type = "access" — refresh tokens are rejected here
	claims, err := token.ParseTyped(tokenStr, token.TypeAccess)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	// Fail closed: Redis failure returns 401, not 500 — deny access on uncertainty
	exists, err := h.authService.ExistsSession(claims.UserID, claims.DeviceID)
	if err != nil || !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   claims.UserID,
		"device_id": claims.DeviceID,
		"exp":       claims.ExpiresAt.Time.Unix(),
	})
}
