package goog

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/bastianrob/go-httputil/adapter"
	"github.com/bastianrob/go-httputil/middleware"
	"github.com/bastianrob/go-oauth/handler"
	"github.com/bastianrob/go-oauth/service"
)

const userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="

type googleCredHandler struct {
	handler.CredentialHandler

	conf        oauth2.Config
	httpAdapter adapter.HTTPAdapter
	service     service.CredentialService
	landing     string
}

//NewGoogleOAuth new instance of CredentialHandler using google OAuth2
func NewGoogleOAuth(conf oauth2.Config,
	httpAdapter adapter.HTTPAdapter,
	service service.CredentialService,
	landing string) handler.CredentialHandler {
	return &googleCredHandler{
		conf:        conf,
		httpAdapter: httpAdapter,
		service:     service,
		landing:     landing,
	}
}

func (goog *googleCredHandler) Login() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			expiry := time.Now().Add(10 * time.Minute)
			cookie := handler.GenerateOauthStateCookie(expiry)
			authURL := goog.conf.AuthCodeURL(cookie.Value)

			http.SetCookie(w, &cookie)
			http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
		}
	}
}

func (goog *googleCredHandler) Callback() middleware.HTTPMiddleware {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Read oauthState from Cookie
			oauthState, _ := r.Cookie("oauthstate")
			if r.FormValue("state") != oauthState.Value {
				log.Println("invalid oauth state")
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte("invalid oauth state"))
				return
			}

			data, err := goog.getUserDataFromGoogle(r.FormValue("code"))
			if err != nil {
				log.Println("failed to get user data from google: " + err.Error())
				w.WriteHeader(http.StatusFailedDependency)
				w.Write([]byte("failed to get user data from google: " + err.Error()))
				return
			}

			googleUserInfo := UserInfo{}
			json.Unmarshal(data, &googleUserInfo)
			accessToken, refreshToken, err := goog.service.Login(r.Context(), googleUserInfo.Email, "")
			if err != nil {
				log.Println("failed to grant JWT: " + err.Error())
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("failed to grant JWT: " + err.Error()))
				return
			}

			w.Header().Set("X-CSRF-Token", accessToken.CSRFToken)
			http.SetCookie(w, &http.Cookie{
				Name:     "access_token",
				Value:    accessToken.Token,
				Domain:   handler.CookieDomain,
				Path:     "/",
				Secure:   handler.CookieSecure, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  accessToken.Expiry,
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "refresh_token",
				Value:    refreshToken.Token,
				Domain:   handler.CookieDomain,
				Path:     "/",
				Secure:   handler.CookieSecure, //HTTPS only
				HttpOnly: true,  //Can't be fetched by JavaScript
				Expires:  refreshToken.Expiry,
			})

			http.Redirect(w, r, goog.landing, http.StatusPermanentRedirect)
		}
	}
}

func (goog *googleCredHandler) getUserDataFromGoogle(code string) ([]byte, error) {
	token, err := goog.conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %s", err.Error())
	}

	response, err := http.Get(userInfoURL + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed read response: %s", err.Error())
	}

	return contents, nil
}
