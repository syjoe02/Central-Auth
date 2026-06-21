// Package server provides the gRPC AuthService implementation.
// It delegates all business logic to service.AuthServiceI and translates
// domain errors to gRPC status codes via domainToGRPCStatus.
//
// Generated stubs (authv1 package) are produced by running `make proto-gen`
// from the monorepo proto/ directory. They are gitignored; CI regenerates them.
package server

import (
	"context"
	"log"

	authv1 "central-auth/gen/go/auth/v1"
	"central-auth/internal/service"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthServer implements authv1.AuthServiceServer.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	svc service.AuthServiceI
}

// New creates a new AuthServer backed by svc.
func New(svc service.AuthServiceI) *AuthServer {
	return &AuthServer{svc: svc}
}

// Signup creates a new identity. Does NOT issue tokens.
// Only email is required; no password credential is set on the Kratos identity.
func (s *AuthServer) Signup(ctx context.Context, req *authv1.SignupRequest) (*authv1.SignupResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	kratosID, err := s.svc.Signup(ctx, req.Email)
	if err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.SignupResponse{
		OryId: kratosID,
		Email: req.Email,
	}, nil
}

// Login issues access + refresh tokens.
// Supports three paths via LoginMethod: PASSWORD, KRATOS_ID, GOOGLE.
func (s *AuthServer) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	ua := nilIfEmpty(req.UserAgent)
	ip := nilIfEmpty(req.Ip)

	var access, refresh string
	var err error

	switch req.Method {
	case authv1.LoginMethod_LOGIN_METHOD_KRATOS_ID:
		if req.KratosId == "" {
			return nil, status.Error(codes.InvalidArgument, "kratos_id is required for KRATOS_ID method")
		}
		access, refresh, err = s.svc.Login(ctx, req.KratosId, req.DeviceId, req.RememberMe, ua, ip)

	case authv1.LoginMethod_LOGIN_METHOD_GOOGLE:
		if req.Email == "" {
			return nil, status.Error(codes.InvalidArgument, "email is required for GOOGLE method")
		}
		access, refresh, err = s.svc.GoogleLogin(ctx, req.Email, req.DeviceId, req.RememberMe, ua, ip)

	default:
		return nil, status.Error(codes.InvalidArgument, "login method is required")
	}

	if err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.LoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// Refresh rotates the refresh token and issues a new access token.
func (s *AuthServer) Refresh(ctx context.Context, req *authv1.RefreshRequest) (*authv1.RefreshResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	access, refresh, err := s.svc.Refresh(ctx, req.RefreshToken)
	if err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.RefreshResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// Logout invalidates the session identified by the refresh token.
func (s *AuthServer) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	if err := s.svc.Logout(ctx, req.RefreshToken); err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.LogoutResponse{}, nil
}

// LogoutAll invalidates all sessions for the identity owning the refresh token.
func (s *AuthServer) LogoutAll(ctx context.Context, req *authv1.LogoutAllRequest) (*authv1.LogoutAllResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	if err := s.svc.LogoutAll(ctx, req.RefreshToken); err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.LogoutAllResponse{}, nil
}

// Verify validates an access token JWT and returns identity claims.
func (s *AuthServer) Verify(ctx context.Context, req *authv1.VerifyRequest) (*authv1.VerifyResponse, error) {
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	result, err := s.svc.VerifyToken(ctx, req.AccessToken)
	if err != nil {
		return nil, domainToGRPCStatus(err)
	}

	return &authv1.VerifyResponse{
		KratosId:  result.KratosID,
		DeviceId:  result.DeviceID,
		ExpiresAt: result.ExpiresAt,
	}, nil
}

// GoogleLogin issues tokens for a Google-authenticated identity.
func (s *AuthServer) GoogleLogin(ctx context.Context, req *authv1.GoogleLoginRequest) (*authv1.GoogleLoginResponse, error) {
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	ua := nilIfEmpty(req.UserAgent)
	ip := nilIfEmpty(req.Ip)

	access, refresh, err := s.svc.GoogleLogin(ctx, req.Email, req.DeviceId, req.RememberMe, ua, ip)
	if err != nil {
		return nil, domainToGRPCStatus(err)
	}

	log.Printf("[gRPC] GoogleLogin success email_prefix=%s", maskEmail(req.Email))

	return &authv1.GoogleLoginResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

// nilIfEmpty returns a pointer to s if s is non-empty, or nil.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// maskEmail truncates the local part of an email for safe log output.
func maskEmail(email string) string {
	for i, c := range email {
		if c == '@' {
			if i > 3 {
				return email[:3] + "...@" + email[i+1:]
			}
			return "***@" + email[i+1:]
		}
	}
	return "***"
}
