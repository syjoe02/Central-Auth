package config

import (
	"fmt"
	"os"
	"time"
)

// ProxyConfig holds configuration for the Kotlin API reverse proxy.
type ProxyConfig struct {
	KotlinURL        string
	DialTimeout      time.Duration
	KotlinServiceKey string // sent as X-Service-Key on every proxied request
}

// LoadProxyConfig reads KOTLIN_URL and KOTLIN_SERVICE_KEY from the environment.
// Fails fast if either variable is absent so misconfiguration is caught at startup.
func LoadProxyConfig() (ProxyConfig, error) {
	u := os.Getenv("KOTLIN_URL")
	if u == "" {
		return ProxyConfig{}, fmt.Errorf("KOTLIN_URL is required")
	}
	key := os.Getenv("KOTLIN_SERVICE_KEY")
	if key == "" {
		return ProxyConfig{}, fmt.Errorf("KOTLIN_SERVICE_KEY is required")
	}
	return ProxyConfig{
		KotlinURL:        u,
		DialTimeout:      3 * time.Second,
		KotlinServiceKey: key,
	}, nil
}
