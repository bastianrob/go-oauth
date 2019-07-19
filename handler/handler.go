package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/bastianrob/go-httputil/middleware"
)

//CredentialHandler interface to handle credential
type CredentialHandler interface {
	Register() middleware.HTTPMiddleware
	Login() middleware.HTTPMiddleware
	Logout() middleware.HTTPMiddleware
	SetClaims() middleware.HTTPMiddleware
	Callback() middleware.HTTPMiddleware
}

//GenerateOauthStateCookie function
//Generate a state token which protects us from CSRF attack
//This token is then must be set to browser's cookie and be validated upon callback
func GenerateOauthStateCookie(expires time.Time) http.Cookie {
	b := make([]byte, 16)
	rand.Read(b)

	state := base64.URLEncoding.EncodeToString(b)
	return http.Cookie{Name: "oauthstate", Value: state, Expires: expires}
}
