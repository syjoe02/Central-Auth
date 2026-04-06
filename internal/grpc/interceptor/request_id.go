package interceptor

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"central-auth/internal/requestid"
)

// RequestID extracts the x-request-id from incoming metadata (if present) or
// generates a new one, then injects it into the context for downstream logging.
func RequestID() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		rid := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if vals := md.Get("x-request-id"); len(vals) > 0 {
				rid = vals[0]
			}
		}
		if rid == "" {
			rid = newRequestID()
		}
		ctx = requestid.WithRequestID(ctx, rid)
		return handler(ctx, req)
	}
}

// RequestIDFromContext returns the request ID stored by RequestID interceptor.
// Delegates to the shared requestid package.
func RequestIDFromContext(ctx context.Context) string {
	return requestid.FromContext(ctx)
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
