# go-oauth

OAuth example using go and google

## Model

```go
type Credential struct {
    ID       string          `json:"id" bson:"_id"`
    Email    string          `json:"email" bson:"email"`
    Password string          `json:"password" bson:"password"`           //Salted + hashed using bcrypt
    Provider string          `json:"provider" bson:"provider"`           //GOOGLE, FACEBOOK, EMAIL
    Claims   json.RawMessage `json:"custom_claims" bson:"custom_claims"` //JWT custom claims
}
```

## API Handlers

```bash
/oauth/google/login -> handler/goog/Login
/oauth/google/callback -> handler/goog/Callback

/oauth/register -> handler/v1/Register
/oauth/login -> handler/v1/Login
/oauth/logout -> handler/v1/Logout
/oauth/claims -> handler/v1/SetClaims
```

## Google Flow

1. User login via /oauth/google/login
2. Redirected to google auth
3. Callback on success to /oauth/google/callback
4. access_token and refresh_token coookies are set
5. X-CSRF-Token returned via headers and must be cached & sent on every request by client

## In house flow

1. User register via /oauth/register
   1. access_token and refresh_token coookies are set
   2. X-CSRF-Token returned via headers and must be cached & sent on every request by client
2. User login via /oauth/login
   1. access_token and refresh_token coookies are set
   2. X-CSRF-Token returned via headers and must be cached & sent on every request by client

## Setting JWT claims

1. POST via /oauth/claims with JSON body
2. access_token and refresh_token coookies are set
3. X-CSRF-Token returned via headers and must be cached & sent on every request by client
