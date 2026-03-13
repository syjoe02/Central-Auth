package token

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret []byte

// InitSecret must be called once at startup before any token operations.
// Panics if JWT_SECRET is missing or under 32 characters.
func InitSecret() {
	s := os.Getenv("JWT_SECRET")
	if len(s) < 32 {
		panic("JWT_SECRET env var must be set and at least 32 characters")
	}
	secret = []byte(s)
}

const (
	TypeAccess  = "access"
	TypeRefresh = "refresh"
)

// ErrWrongTokenType is returned when the token_type claim does not match the expected type.
var ErrWrongTokenType = errors.New("wrong token type")

type Claims struct {
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func Generate(userID, deviceID, tokenType string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID:    userID,
		DeviceID:  deviceID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

func keyfunc(t *jwt.Token) (interface{}, error) {
	if t.Method != jwt.SigningMethodHS256 {
		return nil, errors.New("unexpected signing method")
	}
	return secret, nil
}

// Parse validates signature and expiry. Does not assert token type.
func Parse(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, keyfunc)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// ParseTyped validates signature, expiry, and asserts the token_type claim.
// Use this on all routes that expect a specific token type.
func ParseTyped(tokenStr, expectedType string) (*Claims, error) {
	claims, err := Parse(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != expectedType {
		return nil, ErrWrongTokenType
	}
	return claims, nil
}

// ParseIgnoreExpiry validates signature and token type but permits expired tokens.
// Used exclusively by the logout path — Django's JWTAuthentication blocks logout
// when the access token is expired, so Go must accept an expired refresh token
// to allow the session to be revoked regardless of access token state.
func ParseIgnoreExpiry(tokenStr, expectedType string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, keyfunc)
	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, err
	}
	if token == nil {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	if claims.TokenType != expectedType {
		return nil, ErrWrongTokenType
	}
	return claims, nil
}
