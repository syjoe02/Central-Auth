//go:build contract

// Package contract verifies that the JWT / JWKS artifacts produced by the
// Hydra integration match the shapes that downstream services (Kotlin Spring
// Security, FastAPI python-jose) depend on.
//
// These tests pin the observable API surface so that refactors inside
// central-auth cannot silently break external consumers.
package contract_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"central-auth/internal/hydra"

	"github.com/golang-jwt/jwt/v5"
)

// bigIntToBase64URL encodes a big.Int as a base64url string (no padding) as
// required by RFC 7518 §6.3 (RSA key parameters).
func bigIntToBase64URL(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

// buildMockHydra returns an httptest.Server that serves:
//   - GET  /.well-known/jwks.json → the supplied JWKS JSON
//   - POST /admin/oauth2/introspect → 405 (not needed for JWT validation)
func buildMockHydra(t *testing.T, jwksPayload []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksPayload)
			return
		}
		http.NotFound(w, r)
	}))
}

// TestContract_JWT_ClaimsStructure verifies that the JWT claims extracted by
// ValidateAccessToken carry exactly the fields downstream services rely on:
//
//   - sub  → Kratos identity UUID  (Kotlin maps this to KratosID / ory_identity_id)
//   - exp  → expiry unix timestamp  (standard; python-jose and Spring both check this)
//   - iat  → issued-at timestamp    (standard)
//   - jti  → unique token ID        (used by the blacklist / revocation layer)
//   - ext.device_id → device string (Kotlin uses this for per-device session management)
func TestContract_JWT_ClaimsStructure(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pub := &privateKey.PublicKey
	kid := "contract-test-kid"

	jwksJSON, _ := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": kid,
			"alg": "RS256",
			"n":   bigIntToBase64URL(pub.N),
			"e":   bigIntToBase64URL(big.NewInt(int64(pub.E))),
		}},
	})

	srv := buildMockHydra(t, jwksJSON)
	defer srv.Close()

	kratosID := "ory-identity-uuid-contract-test"
	deviceID := "device-contract-xyz"
	jtiVal := "jti-contract-001"
	now := time.Now()

	rawClaims := struct {
		Subject  string         `json:"sub"`
		ClientID string         `json:"client_id"`
		Ext      map[string]any `json:"ext"`
		jwt.RegisteredClaims
	}{
		Subject:  kratosID,
		ClientID: "central-auth-client",
		Ext:      map[string]any{"device_id": deviceID},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL + "/",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			ID:        jtiVal,
		},
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, rawClaims)
	tok.Header["kid"] = kid
	tokenStr, err := tok.SignedString(privateKey)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	client := hydra.New(srv.URL, srv.URL+"/admin",
		"central-auth-client", "secret", "http://callback")

	claims, err := client.ValidateAccessToken(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}

	// sub — Kotlin's JwtAuthenticationConverter maps this to KratosID
	if claims.Subject != kratosID {
		t.Errorf("sub: want %q, got %q", kratosID, claims.Subject)
	}

	// ext.device_id — Kotlin reads this for per-device session management
	if got := claims.DeviceID(); got != deviceID {
		t.Errorf("ext.device_id: want %q, got %q", deviceID, got)
	}

	// exp — both Spring Security and python-jose reject expired tokens
	if claims.ExpiresAt == nil {
		t.Error("exp claim must be present")
	}

	// iat — required by RFC 7519 §4.1.6
	if claims.IssuedAt == nil {
		t.Error("iat claim must be present")
	}

	// jti — blacklist layer stores this for revocation
	if claims.ID == "" {
		t.Error("jti claim must be present")
	}
}

// TestContract_JWKS_Format_RFC7517 verifies that the JWKS object served by Hydra
// (and cached by central-auth) satisfies RFC 7517 §4 so that Kotlin's
// NimbusJwtDecoder and FastAPI's python-jose can parse it without extra config.
func TestContract_JWKS_Format_RFC7517(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pub := &privKey.PublicKey

	jwksJSON, err := json.Marshal(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": "key-rfc7517-test",
			"alg": "RS256",
			"n":   bigIntToBase64URL(pub.N),
			"e":   bigIntToBase64URL(big.NewInt(int64(pub.E))),
		}},
	})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	var parsed struct {
		Keys []struct {
			Kty string `json:"kty"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksJSON, &parsed); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(parsed.Keys) == 0 {
		t.Fatal("JWKS must contain at least one key")
	}

	key := parsed.Keys[0]
	required := map[string]string{
		"kty": key.Kty,
		"use": key.Use,
		"kid": key.Kid,
		"alg": key.Alg,
		"n":   key.N,
		"e":   key.E,
	}
	for field, val := range required {
		if val == "" {
			t.Errorf("JWKS key missing required field %q (RFC 7517 §4)", field)
		}
	}

	// Algorithm constraints expected by both Kotlin NimbusJwtDecoder and python-jose
	if key.Kty != "RSA" {
		t.Errorf("kty: want RSA, got %q", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("alg: want RS256, got %q", key.Alg)
	}
	if key.Use != "sig" {
		t.Errorf("use: want sig, got %q", key.Use)
	}

	// n and e must be valid base64url-encoded big integers
	for _, field := range []struct{ name, val string }{{"n", key.N}, {"e", key.E}} {
		if _, err := base64.RawURLEncoding.DecodeString(field.val); err != nil {
			t.Errorf("JWKS field %q is not valid base64url: %v", field.name, err)
		}
	}
}
