package handler

import (
	"net/http"

	"central-auth/internal/hydra"

	"github.com/gin-gonic/gin"
)

// AdminHandler handles internal operations that require operator privileges.
// All routes in this handler must be protected by ServiceAuthMiddleware.
type AdminHandler struct {
	hydraClient hydra.ClientI
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(hydraClient hydra.ClientI) *AdminHandler {
	return &AdminHandler{hydraClient: hydraClient}
}

// RefreshJWKS handles POST /admin/jwks/refresh.
//
// Forces an immediate reload of the JWKS public-key cache from Hydra's
// .well-known/jwks.json endpoint. This is the HTTP trigger for zero-downtime
// key rotation; SIGHUP is the Unix signal equivalent.
//
// During a key rotation the previous keys remain valid for the configured
// grace period (BFF_JWKS_GRACE_PERIOD, default 30 minutes) so in-flight
// tokens signed with the old key are not rejected.
func (h *AdminHandler) RefreshJWKS(c *gin.Context) {
	if err := h.hydraClient.ForceRefreshJWKS(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "JWKS refresh failed: " + err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "jwks_refreshed"})
}
