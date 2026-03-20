package config

import "os"

// OryConfig holds the URLs and credentials for Ory Kratos and Hydra.
type OryConfig struct {
	KratosPublicURL string
	KratosAdminURL  string
	HydraPublicURL  string
	HydraAdminURL   string
	HydraClientID   string
	HydraClientSecret string
	HydraRedirectURI  string
}

// LoadOryConfig reads Ory configuration from environment variables.
// Panics if any required variable is missing.
func LoadOryConfig() OryConfig {
	required := map[string]string{
		"KRATOS_PUBLIC_URL":    os.Getenv("KRATOS_PUBLIC_URL"),
		"KRATOS_ADMIN_URL":     os.Getenv("KRATOS_ADMIN_URL"),
		"HYDRA_PUBLIC_URL":     os.Getenv("HYDRA_PUBLIC_URL"),
		"HYDRA_ADMIN_URL":      os.Getenv("HYDRA_ADMIN_URL"),
		"HYDRA_CLIENT_ID":      os.Getenv("HYDRA_CLIENT_ID"),
		"HYDRA_CLIENT_SECRET":  os.Getenv("HYDRA_CLIENT_SECRET"),
	}
	for k, v := range required {
		if v == "" {
			panic("missing required env var: " + k)
		}
	}
	redirectURI := os.Getenv("HYDRA_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = "http://auth-server:8081/internal/oauth/callback"
	}
	return OryConfig{
		KratosPublicURL:   required["KRATOS_PUBLIC_URL"],
		KratosAdminURL:    required["KRATOS_ADMIN_URL"],
		HydraPublicURL:    required["HYDRA_PUBLIC_URL"],
		HydraAdminURL:     required["HYDRA_ADMIN_URL"],
		HydraClientID:     required["HYDRA_CLIENT_ID"],
		HydraClientSecret: required["HYDRA_CLIENT_SECRET"],
		HydraRedirectURI:  redirectURI,
	}
}
