package handler

import (
	"errors"
	"net/http"
	"time"

	"central-auth/internal/config"
	"central-auth/internal/model"
	"central-auth/internal/service"

	"github.com/gin-gonic/gin"
)

const bffCookieName = "__session"

// BFFHandler handles browser-facing BFF endpoints.
// It never returns Hydra tokens in response bodies; the browser only ever
// sees an opaque __session HttpOnly cookie.
type BFFHandler struct {
	bffService service.BFFServiceI
	cfg        config.BFFConfig
}

// NewBFFHandler creates a BFFHandler.
func NewBFFHandler(bffService service.BFFServiceI, cfg config.BFFConfig) *BFFHandler {
	return &BFFHandler{bffService: bffService, cfg: cfg}
}

// Login handles POST /bff/login.
// Accepts the same JSON body shape as the existing /auth/login so that Django
// can drive BFF logins during the migration period.
// On success: sets __session cookie and returns {"status":"authenticated"}.
// Hydra tokens are NEVER included in the response body.
func (h *BFFHandler) Login(c *gin.Context) {
	var req model.BFFLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ua := c.GetHeader("User-Agent")
	ip := c.ClientIP()

	sessionID, err := h.bffService.Login(c.Request.Context(), req.KratosID, req.DeviceID, req.RememberMe, &ua, &ip)
	if err != nil {
		// Do not leak internal error details to the browser.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "login failed"})
		return
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     bffCookieName,
		Value:    sessionID,
		Path:     "/",
		Domain:   h.cfg.CookieDomain,
		MaxAge:   int(h.cfg.SessionTTL.Seconds()),
		Secure:   h.cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	c.JSON(http.StatusOK, model.BFFStatusResponse{Status: "authenticated"})
}

// Logout handles POST /bff/logout.
// Revokes the current session and clears the browser cookie.
func (h *BFFHandler) Logout(c *gin.Context) {
	sessionID := bffSessionID(c)
	if err := h.bffService.Logout(c.Request.Context(), sessionID); err != nil {
		if !errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
			return
		}
	}
	clearBFFCookie(c, h.cfg)
	c.JSON(http.StatusOK, model.BFFStatusResponse{Status: "logged_out"})
}

// LogoutAll handles POST /bff/logout-all.
// Revokes all sessions for the authenticated user across all devices.
func (h *BFFHandler) LogoutAll(c *gin.Context) {
	sessionID := bffSessionID(c)
	if err := h.bffService.LogoutAll(c.Request.Context(), sessionID); err != nil {
		if !errors.Is(err, service.ErrSessionNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout-all failed"})
			return
		}
	}
	clearBFFCookie(c, h.cfg)
	c.JSON(http.StatusOK, model.BFFStatusResponse{Status: "logged_out_all"})
}

// WhoAmI handles GET /bff/whoami.
// Returns the kratosID and deviceID without exposing any token.
func (h *BFFHandler) WhoAmI(c *gin.Context) {
	sessionID := bffSessionID(c)
	kratosID, deviceID, err := h.bffService.WhoAmI(c.Request.Context(), sessionID)
	if err != nil {
		if errors.Is(err, service.ErrSessionBlacklisted) || errors.Is(err, service.ErrSessionNotFound) {
			clearBFFCookie(c, h.cfg)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.JSON(http.StatusOK, model.WhoAmIResponse{
		KratosID: kratosID,
		DeviceID: deviceID,
	})
}

// bffSessionID retrieves the pre-validated session ID set by BFFSessionMiddleware.
// This will be an empty string only if the handler is misconfigured (called without the middleware).
func bffSessionID(c *gin.Context) string {
	v, _ := c.Get("sessionID")
	id, _ := v.(string)
	return id
}

// clearBFFCookie instructs the browser to delete the session cookie immediately.
func clearBFFCookie(c *gin.Context, cfg config.BFFConfig) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     bffCookieName,
		Value:    "",
		Path:     "/",
		Domain:   cfg.CookieDomain,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   cfg.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
