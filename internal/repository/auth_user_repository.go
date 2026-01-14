package repository

type AuthUser struct {
	UserID          string
	Provider        string
	ProviderUserID  string
	Email           string
}

type AuthUserRepository interface {
	FindByProvider(provider, providerUserID string) (*AuthUser, error)
	Create(user *AuthUser) error
}