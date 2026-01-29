package domain

type AuthUser struct {
	UserID     string
	Provider   string
	ProviderID string
	Email      string
}
