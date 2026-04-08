package server

import (
	"errors"

	"central-auth/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// domainToGRPCStatus maps domain-layer sentinel errors to gRPC status errors.
// All unmapped errors default to Internal so internal details never leak to callers.
func domainToGRPCStatus(err error) error {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, service.ErrInvalidToken):
		return status.Error(codes.Unauthenticated, "invalid or expired token")
	case errors.Is(err, service.ErrEmailConflict):
		return status.Error(codes.AlreadyExists, "email already registered")
	default:
		return status.Error(codes.Internal, "internal server error")
	}
}
