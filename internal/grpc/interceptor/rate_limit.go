package interceptor

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RateLimitMethods returns a gRPC interceptor that applies independent token-bucket
// rate limits to specific gRPC methods. Methods not listed in methodLimits pass through
// without being rate-limited by this interceptor (the global RateLimit interceptor
// upstream still applies to all methods).
//
// methodLimits maps a fully-qualified gRPC method name (e.g. "/auth.v1.AuthService/Logout")
// to a requests-per-minute limit. A limit of 0 disables rate limiting for that method.
func RateLimitMethods(methodLimits map[string]int) grpc.UnaryServerInterceptor {
	buckets := make(map[string]*tokenBucket, len(methodLimits))
	for method, rpm := range methodLimits {
		if rpm > 0 {
			buckets[method] = newTokenBucket(rpm)
		}
	}
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		if b, ok := buckets[info.FullMethod]; ok {
			if !b.Allow() {
				return nil, status.Error(codes.ResourceExhausted, "rate limit exceeded")
			}
		}
		return handler(ctx, req)
	}
}

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
