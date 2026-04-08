package interceptor

import (
	"context"
	"time"

	"central-auth/internal/kafka"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// KafkaAccessLog publishes an AccessLogEvent to Kafka after each RPC completes.
// The gRPC method name is used as the path field. UserID is extracted from the
// x-kratos-id metadata when available (set downstream by Verify/Login handlers).
// Publishing is non-blocking — the Producer's internal channel absorbs spikes.
func KafkaAccessLog(publisher kafka.EventPublisher) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		latencyMs := time.Since(start).Milliseconds()

		code := status.Code(err)
		userID := ""
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if vals := md.Get("x-kratos-id"); len(vals) > 0 {
				userID = vals[0]
			}
		}

		publisher.Publish(kafka.AccessLogEvent{
			Path:       info.FullMethod,
			StatusCode: grpcCodeToHTTP(code),
			LatencyMs:  latencyMs,
			UserID:     userID,
			Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		})

		return resp, err
	}
}

// grpcCodeToHTTP maps common gRPC status codes to analogous HTTP status codes
// so the access-log schema remains consistent with the HTTP middleware.
func grpcCodeToHTTP(code codes.Code) int {
	switch code {
	case codes.OK:
		return 200
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return 400
	case codes.Unauthenticated:
		return 401
	case codes.PermissionDenied:
		return 403
	case codes.NotFound:
		return 404
	case codes.AlreadyExists:
		return 409
	case codes.ResourceExhausted:
		return 429
	case codes.Unimplemented:
		return 501
	case codes.Unavailable:
		return 503
	default:
		return 500
	}
}
