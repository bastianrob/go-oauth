package v1

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bastianrob/go-httputil/middleware"
	"github.com/bastianrob/go-oauth/handler"
	"github.com/bastianrob/go-oauth/service"
)

const userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type credentialHandler struct {
	service service.CredentialService
}

//NewCredentialHandler new instance of CredentialHandler using in house authentication
func NewCredentialHandler(service service.CredentialService) handler.CredentialHandler {
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
				log.Println(err.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			accessToken, refreshToken, err := hndl.service.Login(ctx, register.Email, register.Password)
			if err != nil {
				//Do better error handling
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-CSRF-Token", accessToken.CSRFToken)
			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    accessToken.Token,
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  accessToken.Expiry,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken.Token,
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  refreshToken.Expiry,
			})
			http.Redirect(w, r, "/", http.StatusOK)
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
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  accessToken.Expiry,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken.Token,
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
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
				Domain: ".lapelio.com",
				Path:   "/",
				MaxAge: 0,
			})
			http.SetCookie(w, &http.Cookie{
				Name:   "refresh_token",
				Value:  "",
				Domain: ".lapelio.com",
				Path:   "/",
				MaxAge: 0,
			})
			h.ServeHTTP(w, r)
		}
	}
}

func (hndl *credentialHandler) SetClaims() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ctx := r.Context()
			email, ok := ctx.Value(handler.ContextKeyEmail).(string)
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			accessToken, refreshToken, err := hndl.service.SetClaims(ctx, email, body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			w.Header().Set("X-CSRF-Token", accessToken.CSRFToken)
			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    accessToken.Token,
				Domain:   ".lapelio.com",
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  accessToken.Expiry,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken.Token,
				Domain:   ".lapelio.com",
				Path:     "/",
				Secure:   false, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  refreshToken.Expiry,
			})
			w.WriteHeader(http.StatusOK)
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
