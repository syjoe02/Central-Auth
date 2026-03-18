package token_test

import (
	"os"
	"testing"
	"time"

	"central-auth/internal/token"
)

func TestMain(m *testing.M) {
	os.Setenv("JWT_SECRET", "test-secret-that-is-at-least-32-chars!!")
	token.InitSecret()
	os.Exit(m.Run())
}

func TestGenerate_ReturnsNonEmptyToken(t *testing.T) {
	tok, err := token.Generate("user-1", "device-1", token.TypeAccess, time.Minute)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestGenerateAndParse_RoundTrip(t *testing.T) {
	userID := "user-123"
	deviceID := "device-abc"

	tok, err := token.Generate(userID, deviceID, token.TypeAccess, time.Minute)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	claims, err := token.ParseTyped(tok, token.TypeAccess)
	if err != nil {
		t.Fatalf("ParseTyped: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("UserID: got %q, want %q", claims.UserID, userID)
	}
	if claims.DeviceID != deviceID {
		t.Errorf("DeviceID: got %q, want %q", claims.DeviceID, deviceID)
	}
}

func TestParseTyped_WrongType(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeRefresh, time.Minute)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = token.ParseTyped(tok, token.TypeAccess)
	if err == nil {
		t.Fatal("expected error for wrong token type")
	}
}

func TestParseTyped_ExpiredToken(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeAccess, -time.Second)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = token.ParseTyped(tok, token.TypeAccess)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestParseIgnoreExpiry_AcceptsExpiredToken(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeRefresh, -time.Second)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	claims, err := token.ParseIgnoreExpiry(tok, token.TypeRefresh)
	if err != nil {
		t.Fatalf("ParseIgnoreExpiry: %v", err)
	}
	if claims.UserID != "u" {
		t.Errorf("UserID: got %q, want %q", claims.UserID, "u")
	}
}

func TestParseIgnoreExpiry_RejectsWrongType(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeAccess, -time.Second)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = token.ParseIgnoreExpiry(tok, token.TypeRefresh)
	if err == nil {
		t.Fatal("expected error for wrong token type")
	}
}

func TestParseTyped_MalformedToken(t *testing.T) {
	_, err := token.ParseTyped("not.a.token", token.TypeAccess)
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestHash_DeterministicAndNonEmpty(t *testing.T) {
	h1 := token.Hash("some-token")
	h2 := token.Hash("some-token")
	if h1 != h2 {
		t.Error("Hash is not deterministic")
	}
	if h1 == "" {
		t.Error("Hash returned empty string")
	}
	if h1 == "some-token" {
		t.Error("Hash returned input unchanged")
	}
}

func TestGenerate_AccessAndRefreshAreDistinct(t *testing.T) {
	access, err := token.Generate("u", "d", token.TypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := token.Generate("u", "d", token.TypeRefresh, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if access == refresh {
		t.Error("access and refresh tokens should differ")
	}
}

func TestParseTyped_InvalidSignature(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeAccess, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with the signature (last segment)
	tampered := tok[:len(tok)-4] + "XXXX"
	_, err = token.ParseTyped(tampered, token.TypeAccess)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestParseIgnoreExpiry_InvalidSignature(t *testing.T) {
	tok, err := token.Generate("u", "d", token.TypeRefresh, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tampered := tok[:len(tok)-4] + "YYYY"
	_, err = token.ParseIgnoreExpiry(tampered, token.TypeRefresh)
	if err == nil {
		t.Fatal("expected error for tampered signature on expired token")
	}
}

func TestParseIgnoreExpiry_MalformedToken(t *testing.T) {
	_, err := token.ParseIgnoreExpiry("bad.token", token.TypeRefresh)
	if err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestVerifyGoogleIDToken_InvalidToken_ReturnsError(t *testing.T) {
	_, err := token.VerifyGoogleIDToken("not-a-real-token", "test-client-id")
	if err == nil {
		t.Fatal("expected error for invalid Google ID token")
	}
}

func TestGenerateAndParse_RefreshRoundTrip(t *testing.T) {
	userID, deviceID := "user-99", "dev-99"
	tok, err := token.Generate(userID, deviceID, token.TypeRefresh, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := token.ParseTyped(tok, token.TypeRefresh)
	if err != nil {
		t.Fatalf("ParseTyped refresh: %v", err)
	}
	if claims.UserID != userID || claims.DeviceID != deviceID {
		t.Errorf("claims mismatch: got user=%s device=%s", claims.UserID, claims.DeviceID)
	}
}
