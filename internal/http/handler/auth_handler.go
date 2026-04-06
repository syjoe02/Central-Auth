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
// Accepts two forms:
//   - Email+password: {"email","password","device_id","remember_me"} — authenticates via Kratos
//   - Pre-authenticated: {"user_id","device_id","remember_me"} — issues tokens directly (legacy)
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

	var access, refresh string
	var err error

	if req.Email != "" && req.Password != "" {
		// Email+password path: authenticate via Kratos, then issue Hydra tokens.
		access, refresh, err = h.authService.LoginWithPassword(
			c.Request.Context(),
			req.Email, req.Password, req.DeviceID, req.RememberMe,
			uaPtr, ipPtr,
		)
		if err != nil {
			if errors.Is(err, service.ErrInvalidCredentials) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
				return
			}
			log.Printf("Login error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
	} else if req.KratosID != "" {
		// Pre-authenticated path: caller already has a Kratos ID.
		access, refresh, err = h.authService.Login(
			c.Request.Context(),
			req.KratosID, req.DeviceID, req.RememberMe,
			uaPtr, ipPtr,
		)
		if err != nil {
			log.Printf("Login error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "provide either email+password or user_id"})
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

// Signup handles POST /auth/signup.
// Creates a new Kratos identity and returns its UUID.
// Returns 409 if the email is already registered.
func (h *AuthHandler) Signup(c *gin.Context) {
	var req model.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	kratosID, err := h.authService.Signup(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrEmailConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
			return
		}
		log.Printf("Signup error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "signup failed"})
		return
	}

	c.JSON(http.StatusCreated, model.SignupResponse{
		OryID: kratosID,
		Email: req.Email,
	})
}

// GoogleLogin handles POST /auth/google/login.
// Called by Django's CentralAuthAdapter after a successful Kratos Google OIDC flow.
// The email has already been verified by Kratos; we look up the identity and issue tokens.
//
// Request body: {"email","device_id","remember_me"}
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	var req struct {
		Email      string `json:"email" binding:"required,email"`
		DeviceID   string `json:"device_id" binding:"required"`
		RememberMe bool   `json:"remember_me"`
	}
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

	access, refresh, err := h.authService.GoogleLogin(
		c.Request.Context(),
		req.Email, req.DeviceID, req.RememberMe,
		uaPtr, ipPtr,
	)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "google account not registered"})
			return
		}
		log.Printf("GoogleLogin error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.JSON(http.StatusOK, model.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
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
