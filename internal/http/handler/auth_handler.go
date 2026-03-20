package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"central-auth/internal/model"
	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

// AuthHandler handles all /auth/* endpoints using the Ory-backed AuthServiceI.
type AuthHandler struct {
	authService service.AuthServiceI
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(authService service.AuthServiceI) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// bearerToken extracts the Bearer token from the Authorization header.
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

// isTokenError returns true for errors that should map to HTTP 401 rather than 500.
func isTokenError(err error) bool {
	return errors.Is(err, service.ErrInvalidToken)
}

// Login handles POST /auth/login.
// The caller (e.g. Django) has already authenticated the user and passes the
// Kratos identity ID as "user_id" in the JSON body.
func (h *AuthHandler) Login(c *gin.Context) {
	var req model.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userAgent := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	var uaPtr, ipPtr *string
	if userAgent != "" {
		uaPtr = &userAgent
	}
	if ip != "" {
		ipPtr = &ip
	}

	access, refresh, err := h.authService.Login(
		c.Request.Context(),
		req.KratosID,
		req.DeviceID,
		req.RememberMe,
		uaPtr,
		ipPtr,
	)
	if err != nil {
		log.Printf("Login error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, model.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

// Logout handles POST /auth/logout.
// Expects Authorization: Bearer <hydra-refresh-token>.
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.Logout(c.Request.Context(), refreshToken); err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			log.Printf("Logout error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout_failed", "error_code": "server_error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "logged_out"})
}

// LogoutAll handles POST /auth/logout-all.
// Expects Authorization: Bearer <hydra-refresh-token>.
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	refreshToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	if err := h.authService.LogoutAll(c.Request.Context(), refreshToken); err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "logout_all_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			log.Printf("LogoutAll error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout_all_failed", "error_code": "server_error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"result": "logged_out_all"})
}

// Refresh handles POST /auth/refresh.
// Expects Authorization: Bearer <hydra-refresh-token>.
// Returns a new access+refresh token pair.
func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization header"})
		return
	}

	accessToken, newRefreshToken, err := h.authService.Refresh(c.Request.Context(), refreshToken)
	if err != nil {
		if isTokenError(err) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh_failed", "error_code": "token_invalid", "reason": err.Error()})
		} else {
			log.Printf("Refresh error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "refresh_failed", "error_code": "server_error"})
		}
		return
	}

	c.JSON(http.StatusOK, model.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	})
}

// Verify handles POST /auth/verify.
// Expects Authorization: Bearer <hydra-access-token>.
// Validates the JWT locally via Hydra's JWKS — no Hydra round-trip on the hot path.
// Fail-closed: any validation error returns 401.
func (h *AuthHandler) Verify(c *gin.Context) {
	tokenStr, ok := bearerToken(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}

	// Fail-closed: any error → 401 (same behaviour as the previous Redis ExistsSession check)
	result, err := h.authService.VerifyToken(c.Request.Context(), tokenStr)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user_id":   result.KratosID,
		"device_id": result.DeviceID,
		"exp":       result.ExpiresAt,
	})
}
