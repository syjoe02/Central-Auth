package interceptor

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// Logging logs method name, request ID, latency, and status code for every call.
func Logging() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		elapsed := time.Since(start)

		code := status.Code(err)
		rid := RequestIDFromContext(ctx)
		log.Printf("[gRPC] method=%s request_id=%s code=%s latency=%s", info.FullMethod, rid, code, elapsed)

		return resp, err
	}
}
