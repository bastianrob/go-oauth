package model

import (
	"os"
	"time"

	//OS ENV taken from file
	_ "github.com/joho/godotenv/autoload"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	issuer          = ""
	secret          = ""
	authduration    = 1 * time.Hour
	refreshduration = 24 * 7 * time.Hour
)

func init() {
	issuer = os.Getenv("JWT_ISSUER")
	secret = os.Getenv("JWT_SECRET")
	dur, err := time.ParseDuration(os.Getenv("JWT_AUTH_DURATION"))
	if err == nil {
		authduration = dur
	}

	refreshduration, err = time.ParseDuration(os.Getenv("JWT_REFRESH_DURATION"))
	if err == nil {
		refreshduration = dur
	}
}

//AuthClaims custom claims to be embedded in Auth Token
type AuthClaims struct {
	jwt.StandardClaims
	CSRFToken    string                 `json:"csrf,omitempty"`
	CustomClaims map[string]interface{} `json:"ccm,omitempty"`
}
