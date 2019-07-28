package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/bastianrob/go-httputil/middleware"
	"github.com/bastianrob/go-oauth/model"
)

//Context key collection
const (
	ContextKeyEmail  = ContextKey("email")
	ContextKeyClaims = ContextKey("claims")
)

// ContextKey for middleware
type ContextKey string

const contextKeyPrefix = "auth middleware "

func (c ContextKey) String() string {
	return contextKeyPrefix + string(c)
}

//Authenticate JWT Access token
func Authenticate() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("access_token")
			if err != nil || cookie == nil {
				//log access token cookie not found
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			cred := model.Credential{}
			authClaims, err := cred.FromJWT(cookie.Value)
			/*
				Disable it for now, wrong implementation?
				csrf := r.Header.Get("X-CSRF-Token")
				if csrf == "" || csrf != authClaims.CSRFToken {
					//Wrong CSRF token, being attacked?
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			*/

			now := time.Now()
			if now.Unix() > authClaims.StandardClaims.ExpiresAt {
				//Expired
				//TODO refresh token
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyEmail, cred.Email)
			ctx = context.WithValue(ctx, ContextKeyClaims, authClaims)
			r = r.WithContext(ctx)
			h.ServeHTTP(w, r)
		}
	}
}
