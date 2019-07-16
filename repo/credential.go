package repo

import (
	"context"
	"errors"

	"github.com/bastianrob/go-oauth/model"
)

//Error collection
var (
	ErrNotFound = errors.New("Object Not Found")
)

//CredentialRepo interface to access credential resource
type CredentialRepo interface {
	Count(ctx context.Context, email string) int
	Get(ctx context.Context, email string) (model.Credential, error)
	Create(ctx context.Context, cred model.Credential) error
}
