package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bastianrob/go-oauth/repo/mongorepo"
	"github.com/gorilla/handlers"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/bastianrob/go-httputil/adapter"
	"github.com/bastianrob/go-httputil/middleware"
	"github.com/bastianrob/go-oauth/handler"

	oauth "github.com/bastianrob/go-oauth/handler"
	googleHandler "github.com/bastianrob/go-oauth/handler/goog"
	inHouseHandler "github.com/bastianrob/go-oauth/handler/v1"
	googleService "github.com/bastianrob/go-oauth/service/goog"
	inHouseService "github.com/bastianrob/go-oauth/service/v1"
	_ "github.com/joho/godotenv/autoload"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func initMongoClient() *mongo.Client {
	mongoConn := os.Getenv("MONGO_CONN")
	mongoClient, err := mongo.NewClient(options.Client().ApplyURI(mongoConn))
	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = mongoClient.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	return mongoClient
}

func main() {
	googleOAuthConfig := oauth2.Config{
		RedirectURL:  os.Getenv("OAUTH_GOOGLE_REDIRECT_URL"),
		ClientID:     os.Getenv("OAUTH_GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
		Scopes:       strings.Split(os.Getenv("OAUTH_GOOGLE_SCOPES"), ","),
		Endpoint:     google.Endpoint,
	}

	mongoClient := initMongoClient()
	credentialRepo := mongorepo.NewCredentialRepo(mongoClient.Database("credential"))
	googleCredentialService := googleService.NewGoogleCredentialService(credentialRepo)

	httpAdapter := adapter.NewHTTPAdapter(&http.Client{})
	googleOAuthAPIHandler := googleHandler.NewGoogleOAuth(
		googleOAuthConfig,
		httpAdapter,
		googleCredentialService,
		os.Getenv("OAUTH_LANDING_URL"))

	inHouseServiceCredentialService := inHouseService.NewCredentialService(credentialRepo)
	inHouseOAuthAPIHandler := inHouseHandler.NewCredentialHandler(inHouseServiceCredentialService)

	r := httprouter.New()
	healthcheck(r)
	googleOAuthRoutes(r, googleOAuthAPIHandler)
	inHouseRoutes(r, inHouseOAuthAPIHandler)

	router := handlers.CombinedLoggingHandler(os.Stdout, r)
	router = handlers.RecoveryHandler()(router)
	router = cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:*",
			"http://lapelio.com",
			"https://lapelio.com",
			"http://*.lapelio.com",
			"https://*.lapelio.com",
		},
		AllowCredentials: true,
		AllowedMethods: []string{
			http.MethodHead,
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{"*"},
	}).Handler(router)

	log.Println("Serving :7000")
	log.Fatal(http.ListenAndServe(":7000", router))
}

func pipe(endpoint func() middleware.HTTPMiddleware) http.HandlerFunc {
	return middleware.NewPipeline().
		//Do(oauth.Authenticate()). //Authenticate user
		Do(endpoint()).
		For(func(w http.ResponseWriter, r *http.Request) {})
}

func auth(endpoint func() middleware.HTTPMiddleware) http.HandlerFunc {
	return middleware.NewPipeline().
		Do(oauth.Authenticate()). //Authenticate user
		Do(endpoint()).
		For(func(w http.ResponseWriter, r *http.Request) {})
}

func healthcheck(router *httprouter.Router) {
	router.GET("/health", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		w.WriteHeader(http.StatusOK)
	})
}

func googleOAuthRoutes(router *httprouter.Router, h handler.CredentialHandler) {
	router.HandlerFunc("GET", "/oauth/google/login", pipe(h.Login))
	router.HandlerFunc("GET", "/oauth/google/callback", pipe(h.Callback))
}

func inHouseRoutes(router *httprouter.Router, h handler.CredentialHandler) {
	router.HandlerFunc("POST", "/oauth/login", pipe(h.Login))
	router.HandlerFunc("GET", "/oauth/logout", pipe(h.Logout))
	router.HandlerFunc("POST", "/oauth/register", pipe(h.Register))
	router.HandlerFunc("POST", "/oauth/claims", auth(h.SetClaims))
}
