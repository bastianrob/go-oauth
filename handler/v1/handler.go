package v1

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/bastianrob/go-httputil/adapter"
	"github.com/bastianrob/go-httputil/middleware"
	"github.com/bastianrob/go-oauth/handler"
	"github.com/bastianrob/go-oauth/service"
)

const userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type credentialHandler struct {
	service service.CredentialService
}

//NewCredentialService new instance of CredentialHandler using in house authentication
func NewCredentialService(conf oauth2.Config, httpAdapter adapter.HTTPAdapter, service service.CredentialService) handler.CredentialHandler {
	return &credentialHandler{service: service}
}

func (hndl *credentialHandler) Register() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			register := RegisterInfo{}
			err = json.Unmarshal(body, &register)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			err = hndl.service.Register(ctx, register.Email, register.Password, register.ConfirmPassword)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusCreated)
			h.ServeHTTP(w, r)
		}
	}
}

func (hndl *credentialHandler) Login() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			login := LoginInfo{}
			err = json.Unmarshal(body, &login)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			accessToken, refreshToken, err := hndl.service.Login(ctx, login.Email, login.Password)
			if err != nil {
				//Do better error handling
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-CSRF-Token", accessToken.CSRFToken)
			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    accessToken.Token,
				Secure:   true, //HTTPS only
				HttpOnly: true, //Can't be fetched by JavaScript
				Expires:  accessToken.Expiry,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken.Token,
				Secure:   true, //HTTPS only
				HttpOnly: true, //Can't be fetched by JavaScript
				Expires:  refreshToken.Expiry,
			})
			http.Redirect(w, r, "/", http.StatusOK)
			h.ServeHTTP(w, r)
		}
	}
}

func (hndl *credentialHandler) Logout() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-CSRF-Token", "")
			http.SetCookie(w, &http.Cookie{
				Name:   "access_token",
				Value:  "",
				MaxAge: 0,
			})
			http.SetCookie(w, &http.Cookie{
				Name:   "refresh_token",
				Value:  "",
				MaxAge: 0,
			})
			h.ServeHTTP(w, r)
		}
	}
}

func (hndl *credentialHandler) Callback() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotImplemented)
		}
	}
}
