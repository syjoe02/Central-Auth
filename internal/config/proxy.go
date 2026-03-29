package config

import (
	"fmt"
	"os"
	"time"
)

// ProxyConfig holds configuration for the Django API reverse proxy.
type ProxyConfig struct {
	DjangoURL   string
	DialTimeout time.Duration
}

// LoadProxyConfig reads DJANGO_URL from the environment.
// Fails fast if the variable is absent so misconfiguration is caught at startup.
func LoadProxyConfig() (ProxyConfig, error) {
	u := os.Getenv("DJANGO_URL")
	if u == "" {
		return ProxyConfig{}, fmt.Errorf("DJANGO_URL is required")
	}
	return ProxyConfig{
		DjangoURL:   u,
		DialTimeout: 3 * time.Second,
	}, nil
}
