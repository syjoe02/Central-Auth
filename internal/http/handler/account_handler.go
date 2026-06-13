package handler

import (
	"errors"
	"log"
	"net/http"

	"central-auth/internal/model"
	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

// AccountHandler handles /bff/account/* and /bff/logout-devices endpoints.
type AccountHandler struct {
	accountService service.AccountServiceI
}

// NewAccountHandler creates an AccountHandler.
func NewAccountHandler(accountService service.AccountServiceI) *AccountHandler {
	return &AccountHandler{accountService: accountService}
}

// GetMe handles GET /bff/account/me.
func (h *AccountHandler) GetMe(c *gin.Context) {
	sessionID := bffSessionID(c)
	if sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
		return
	}
	me, err := h.accountService.GetMe(c.Request.Context(), sessionID)
	if err != nil {
		log.Printf("[ACCOUNT] GetMe error: %v", err)
		if errors.Is(err, service.ErrSessionBlacklisted) || errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch account info"})
		return
	}
	c.JSON(http.StatusOK, me)
}

// GetSessions handles GET /bff/account/sessions.
func (h *AccountHandler) GetSessions(c *gin.Context) {
	sessionID := bffSessionID(c)
	if sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
		return
	}
	sessions, err := h.accountService.GetSessions(c.Request.Context(), sessionID)
	if err != nil {
		log.Printf("[ACCOUNT] GetSessions error: %v", err)
		if errors.Is(err, service.ErrSessionBlacklisted) || errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch sessions"})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

// LogoutDevices handles POST /bff/logout-devices.
func (h *AccountHandler) LogoutDevices(c *gin.Context) {
	var req model.LogoutDevicesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: deviceIds must be a non-empty array"})
		return
	}
	sessionID := bffSessionID(c)
	if sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
		return
	}
	if err := h.accountService.LogoutDevices(c.Request.Context(), sessionID, req.DeviceIDs); err != nil {
		log.Printf("[ACCOUNT] LogoutDevices error: %v", err)
		if errors.Is(err, service.ErrSessionBlacklisted) || errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout devices"})
		return
	}
	c.JSON(http.StatusOK, model.BFFStatusResponse{Status: "devices_logged_out"})
}

// LogoutOtherDevices handles POST /bff/logout-other-devices.
func (h *AccountHandler) LogoutOtherDevices(c *gin.Context) {
	sessionID := bffSessionID(c)
	if sessionID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
		return
	}
	if err := h.accountService.LogoutOtherDevices(c.Request.Context(), sessionID); err != nil {
		log.Printf("[ACCOUNT] LogoutOtherDevices error: %v", err)
		if errors.Is(err, service.ErrSessionBlacklisted) || errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout other devices"})
		return
	}
	c.JSON(http.StatusOK, model.BFFStatusResponse{Status: "other_devices_logged_out"})
}
