package token

import (
	"context"
	"errors"

	"google.golang.org/api/idtoken"
)

type GoogleClaims struct {
	Subject string
	Email   string
	Name    string
}

func VerifyGoogleIDToken(idToken string, clientID string) (*GoogleClaims, error) {
	payload, err := idtoken.Validate(context.Background(), idToken, clientID)
	if err != nil {
		return nil, err
	}

	sub, ok := payload.Claims["sub"].(string)
	if !ok {
		return nil, errors.New("missing sub")
	}

	email, _ := payload.Claims["email"].(string)
	name, _ := payload.Claims["name"].(string)

	return &GoogleClaims{
		Subject: sub,
		Email:   email,
		Name:    name,
	}, nil
}