// Package interceptor provides unary gRPC server interceptors for the auth service.
package interceptor

import (
	"context"
	"log"
	"runtime/debug"

	"github.com/getsentry/sentry-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Recovery catches panics in downstream handlers and converts them to
// codes.Internal status errors, preventing the gRPC server from crashing.
func Recovery() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[gRPC][PANIC] method=%s panic=%v\n%s", info.FullMethod, r, debug.Stack())
				sentry.CurrentHub().Recover(r)
				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}
