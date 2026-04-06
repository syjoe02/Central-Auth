package interceptor

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ServiceAuth rejects any request whose x-service-key metadata value does not
// match the expected key using constant-time comparison to prevent timing attacks.
func ServiceAuth(expectedKey string) grpc.UnaryServerInterceptor {
	expected := []byte(expectedKey)
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		vals := md.Get("x-service-key")
		if len(vals) == 0 {
			return nil, status.Error(codes.Unauthenticated, "missing x-service-key")
		}

		if subtle.ConstantTimeCompare([]byte(vals[0]), expected) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid service key")
		}

		return handler(ctx, req)
	}
}
