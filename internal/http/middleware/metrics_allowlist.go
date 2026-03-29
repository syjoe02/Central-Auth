package middleware

import (
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// MetricsAllowlistHandler wraps next with a double-lock: IP CIDR allowlist
// AND HTTP Basic Auth. Both checks must pass independently.
//
// IP check (METRICS_ALLOWED_CIDR):
//   - Empty env var → open access with a warning (development fallback).
//   - IP not in any listed CIDR → 403 (empty body, no metric names leaked).
//
// Basic Auth check (user / password parameters):
//   - Both empty → check skipped (development fallback, CIDR-only mode).
//   - Credentials present but missing/wrong Authorization header → 401 +
//     WWW-Authenticate challenge.
//
// Order: IP is checked first; 403 is returned before the Basic Auth challenge
// so that unauthorised scrapers cannot probe for valid credentials.
func MetricsAllowlistHandler(user, password string, next http.Handler) http.Handler {
	raw := os.Getenv("METRICS_ALLOWED_CIDR")

	var nets []*net.IPNet

	if raw == "" {
		log.Println("[WARN] METRICS_ALLOWED_CIDR is not set — /metrics is accessible from all addresses")
	} else {
		for _, cidr := range strings.Split(raw, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				panic("METRICS_ALLOWED_CIDR contains invalid CIDR " + cidr + ": " + err.Error())
			}
			nets = append(nets, ipNet)
		}
		log.Printf("[INFO] Metrics allowlist configured: %s", raw)
	}

	basicAuthEnabled := user != "" && password != ""
	if basicAuthEnabled {
		log.Printf("[INFO] Metrics Basic Auth enabled (user: %s)", user)
	} else {
		log.Println("[WARN] METRICS_BASIC_AUTH_USER/PASSWORD not set — /metrics Basic Auth disabled")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ── Lock 1: IP CIDR allowlist ──────────────────────────────────────────
		if len(nets) > 0 {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			ip := net.ParseIP(host)
			if ip == nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			allowed := false
			for _, n := range nets {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		// ── Lock 2: HTTP Basic Auth ────────────────────────────────────────────
		if basicAuthEnabled {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Basic ") {
				w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			decoded, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			userMatch := subtle.ConstantTimeCompare([]byte(parts[0]), []byte(user)) == 1
			passMatch := subtle.ConstantTimeCompare([]byte(parts[1]), []byte(password)) == 1
			if !userMatch || !passMatch {
				w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
