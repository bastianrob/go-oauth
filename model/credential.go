package model

import (
	"errors"
	"net/mail"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//Credential data model
type Credential struct {
	ID       string                 `json:"id" bson:"_id,omitempty"`
	Email    string                 `json:"email" bson:"email,omitempty"`
	Password string                 `json:"password" bson:"password,omitempty"` //Salted + hashed using bcrypt
	Provider string                 `json:"provider" bson:"provider,omitempty"` //GOOGLE, FACEBOOK, EMAIL
	Claims   map[string]interface{} `json:"custom_claims" bson:"custom_claims"`
}

//Create initialize new credential
func (cred *Credential) Create(email, pass, provider string) *Credential {
	cred.ID = uuid.New().String()
	cred.Email = email
	cred.Provider = provider

	if pass != "" {
		passhash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
		cred.Password = string(passhash)
	}
	return cred
}

//Validate credential data
func (cred *Credential) Validate() error {
	errs := []string{}

	if cred.Email == "" {
		errs = append(errs, ErrCredentialEmailEmpty.Error())
	}

	if _, err := mail.ParseAddress(cred.Email); err != nil {
		errs = append(errs, ErrCredentialEmailMalformed.Error())
	}

	if cred.Provider == "" {
		errs = append(errs, ErrCredentialProviderEmpty.Error())
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "\n"))
	}

	return nil
}

//VerifyPassword compares credential stored (bcrypt hashed) password, with plain text password
func (cred *Credential) VerifyPassword(plainPass string) error {
	return bcrypt.CompareHashAndPassword([]byte(cred.Password), []byte(plainPass))
}

//GenerateJWT token with one hour token expiration
//Returns JWT Token, CSRF token, and Expiry time
func (cred *Credential) GenerateJWT() (AccessToken, RefreshToken, error) {
	//Generate Access Token
	exp := time.Now().Add(authduration)
	csrf := uuid.New().String()
	authclaims := AuthClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    issuer,
			ExpiresAt: exp.Unix(),
			Subject:   cred.Email,
		},
		CSRFToken:    csrf,
		CustomClaims: cred.Claims,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &authclaims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return AccessToken{}, RefreshToken{}, err
	}
	accessToken := AccessToken{Token: tokenString, CSRFToken: csrf, Expiry: exp}

	//Generate Refresh Token
	id := uuid.New().String()
	exp = time.Now().Add(refreshduration)
	refreshclaims := jwt.StandardClaims{
		Id:        id,
		ExpiresAt: exp.Unix(),
		Subject:   cred.Email,
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, &refreshclaims)
	tokenString, err = token.SignedString([]byte(secret))
	if err != nil {
		return AccessToken{}, RefreshToken{}, err
	}
	refreshToken := RefreshToken{ID: id, Token: tokenString, Expiry: exp}

	//Sucess
	return accessToken, refreshToken, nil
}

//FromJWT parse access token into credential
func (cred *Credential) FromJWT(tokenString string) (AuthClaims, error) {
	authClaims := AuthClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &authClaims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if err != nil || !token.Valid {
		return AuthClaims{}, errors.New("Invalid Token")
	}

	cred.Email = authClaims.Subject
	cred.Claims = authClaims.CustomClaims
	return authClaims, nil
}
