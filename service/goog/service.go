package goog

import (
	"context"

	"github.com/bastianrob/go-oauth/model"
	"github.com/bastianrob/go-oauth/repo"
	"github.com/bastianrob/go-oauth/service"
)

const (
	provider = "GOOGLE"
)

//CredentialService implementation for google sign in
type googleCredentialService struct {
	service.CredentialService //Implements Credential Service

	repo repo.CredentialRepo
}

//NewGoogleCredentialService new instance of CredentialService using google OAuth2
func NewGoogleCredentialService(repo repo.CredentialRepo) service.CredentialService {
	return &googleCredentialService{repo: repo}
}

//Register via google is not implemented
func (svc *googleCredentialService) Register(ctx context.Context, email, password, confirmPass string) error {
	return service.ErrNotImplemented
}

//Login via google
//Use user info to either register the user or sign in
//Return token string
func (svc *googleCredentialService) Login(ctx context.Context, email, password string) (model.AccessToken, model.RefreshToken, error) {
	cred, err := svc.repo.Get(ctx, email)
	if err == repo.ErrNotFound {
		//not found, create a new credential
		cred.Create(email, "", provider)
		err := svc.repo.Create(ctx, cred)
		if err != nil {
			//error 500 failed to create user
			return model.AccessToken{}, model.RefreshToken{}, err
		}
	} else if err != nil {
		//error 500 unknown error occured
		return model.AccessToken{}, model.RefreshToken{}, err
	}

	return cred.GenerateJWT()
}
