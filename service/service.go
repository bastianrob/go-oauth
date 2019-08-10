package service

import (
	"context"
	"encoding/json"

	"github.com/bastianrob/go-oauth/model"
)

//CredentialService Contract
type CredentialService interface {
	Register(ctx context.Context, email, password, confirmPass string, claims map[string]interface{}) error
	Login(ctx context.Context, email, password string) (model.AccessToken, model.RefreshToken, error)
	Get(ctx context.Context, email string) (model.Credential, error)
	SetClaims(ctx context.Context, email string, claims json.RawMessage) (model.AccessToken, model.RefreshToken, error)
}
