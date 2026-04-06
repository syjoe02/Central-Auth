// Package requestid provides a shared context key for propagating request IDs
// across layers (gRPC interceptors, HTTP middleware, service, resilience).
// Both the injector (gRPC/HTTP middleware) and the reader (service, resilience)
// import this package so the same key type is used for context.WithValue lookups.
package requestid

import "context"

type contextKey struct{}

// WithRequestID returns a copy of ctx with id stored under the package-local key.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// FromContext returns the request ID stored by WithRequestID.
// Returns "" if the context carries no request ID.
func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKey{}).(string)
	return v
}
