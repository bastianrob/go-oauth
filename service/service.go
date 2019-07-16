package service

import (
	"context"

	"github.com/bastianrob/go-oauth/model"
)

//CredentialService Contract
type CredentialService interface {
	Register(ctx context.Context, email, password, confirmPass string) error
	Login(ctx context.Context, email, password string) (model.AccessToken, model.RefreshToken, error)
	Get(ctx context.Context, email string) (model.Credential, error)
}
