package interceptor

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

var (
	grpcRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "central_auth",
		Subsystem: "grpc",
		Name:      "requests_total",
		Help:      "Total number of gRPC requests by method and status code.",
	}, []string{"method", "code"})

	grpcRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "central_auth",
		Subsystem: "grpc",
		Name:      "request_duration_seconds",
		Help:      "gRPC request latency histogram.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"method"})
)

// Prometheus records request counts and latencies for every gRPC method.
func Prometheus() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		elapsed := time.Since(start)

		code := status.Code(err).String()
		grpcRequestsTotal.WithLabelValues(info.FullMethod, code).Inc()
		grpcRequestDuration.WithLabelValues(info.FullMethod).Observe(elapsed.Seconds())

		return resp, err
	}
}
