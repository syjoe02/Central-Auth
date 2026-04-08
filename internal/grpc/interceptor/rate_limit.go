package interceptor

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RateLimit returns a no-op interceptor when limit == 0 (disabled).
// When limit > 0 it applies a token-bucket per-method limit backed by an
// in-process counter. For distributed rate-limiting wire a Redis-backed limiter.
func RateLimit(requestsPerMinute int) grpc.UnaryServerInterceptor {
	if requestsPerMinute <= 0 {
		// Rate limiting disabled — pass through.
		return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
			return handler(ctx, req)
		}
	}

	limiter := newTokenBucket(requestsPerMinute)
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if !limiter.Allow() {
			return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
		}
		return handler(ctx, req)
	}
}
