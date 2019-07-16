package goog

import (
	"context"

	"github.com/bastianrob/go-oauth/model"
	"github.com/bastianrob/go-oauth/repo"
	"github.com/bastianrob/go-oauth/service"
)

const (
	provider = "EMAIL"
)

//CredentialService implementation for in house sign in
type credentialService struct {
	repo repo.CredentialRepo
}

//NewCredentialService new instance of CredentialService using in house service
func NewCredentialService(repo repo.CredentialRepo) service.CredentialService {
	return &credentialService{repo}
}

//Register via in house service
func (svc *credentialService) Register(ctx context.Context, email, password, confirmPass string) error {
	//Construct credentail object from request
	cred := model.Credential{}
	cred.Create(email, password, provider)

	//Validate the credential data
	err := cred.Validate()
	if err != nil {
		return err
	}

	//Verify that password and confirmation password is equal
	err = cred.VerifyPassword(confirmPass)
	if err != nil {
		return err
	}

	//Check duplicate email
	_, err = svc.repo.Get(ctx, email)
	if err != repo.ErrNotFound {
		return service.ErrAlreadyExists
	}

	//Every pre-check passed, create a credential
	err = svc.repo.Create(ctx, cred)
	if err != nil {
		//error 500 failed to create user
		return err
	}

	//success, return no error
	return nil
}

//Login via in house service
//Use user info to either register the user or sign in
//Return token string
func (svc *credentialService) Login(ctx context.Context, email, password string) (model.AccessToken, model.RefreshToken, error) {
	cred, err := svc.repo.Get(ctx, email)
	if err == repo.ErrNotFound {
		//user not found, cannot login
		return model.AccessToken{}, model.RefreshToken{}, service.ErrNotFound
	} else if err != nil {
		//Error 500: unknown error, cannot login
		return model.AccessToken{}, model.RefreshToken{}, err
	}

	err = cred.VerifyPassword(password)
	if err != nil {
		//wrong password, cannot login
		return model.AccessToken{}, model.RefreshToken{}, err
	}

	//Success, create JWT token
	return cred.GenerateJWT()
}

//Get one credential by email
func (svc *credentialService) Get(ctx context.Context, email string) (model.Credential, error) {
	cred, err := svc.repo.Get(ctx, email)
	if err == repo.ErrNotFound {
		//user not found, cannot login
		return cred, service.ErrNotFound
	}

	return cred, err
}
