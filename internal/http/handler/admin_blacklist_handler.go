package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"central-auth/internal/repository"
	"central-auth/internal/service"
)

// AdminBlacklistHandler exposes block/unblock endpoints under the admin group.
// All routes are protected by ServiceAuthMiddleware (X-Service-Key header).
type AdminBlacklistHandler struct {
	svc *service.AdminBlacklistService
}

// NewAdminBlacklistHandler constructs an AdminBlacklistHandler.
func NewAdminBlacklistHandler(svc *service.AdminBlacklistService) *AdminBlacklistHandler {
	return &AdminBlacklistHandler{svc: svc}
}

type blockRequest struct {
	TargetType  string `json:"target_type" binding:"required,oneof=USER JTI SERVICE_KEY"`
	TargetValue string `json:"target_value" binding:"required,max=512"`
	Reason      string `json:"reason" binding:"max=1024"`
}

type unblockRequest struct {
	TargetType  string `json:"target_type" binding:"required,oneof=USER JTI SERVICE_KEY"`
	TargetValue string `json:"target_value" binding:"required,max=512"`
}

// Block registers a global block for the given target.
// POST /admin/blacklist/block
//
// Request body:
//
//	{
//	  "target_type":  "USER" | "JTI" | "SERVICE_KEY",
//	  "target_value": "<kratos_id | jti | service_key_value>",
//	  "reason":       "<optional human-readable reason>"
//	}
func (h *AdminBlacklistHandler) Block(c *gin.Context) {
	var req blockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := h.svc.Block(c.Request.Context(), repository.BlacklistTargetType(req.TargetType), req.TargetValue, req.Reason); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "block failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "blocked", "target_type": req.TargetType, "target_value": req.TargetValue})
}

// Unblock removes a global block for the given target.
// DELETE /admin/blacklist/block
//
// Request body:
//
//	{
//	  "target_type":  "USER" | "JTI" | "SERVICE_KEY",
//	  "target_value": "<value to unblock>"
//	}
func (h *AdminBlacklistHandler) Unblock(c *gin.Context) {
	var req unblockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if err := h.svc.Unblock(c.Request.Context(), repository.BlacklistTargetType(req.TargetType), req.TargetValue); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unblock failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "unblocked", "target_type": req.TargetType, "target_value": req.TargetValue})
}
