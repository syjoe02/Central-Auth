package token

import (
	"time"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var Secret = []byte("CHANGE_THIS_SECRET")

type Claims struct {
	UserID string `json:"user_id"`
	DeviceID string `json:"device_id"`
	jwt.RegisteredClaims
}

func Generate(userID string, deviceID string, ttl time.Duration) (string, error) {
	claims := Claims{
		UserID: userID,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(Secret)
}

func Parse(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tokenStr,
		&Claims{},
		func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return Secret, nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}