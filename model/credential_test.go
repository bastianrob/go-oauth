package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCredential_Create(t *testing.T) {
	type args struct {
		email    string
		pass     string
		provider string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"ok", args{
				email:    "test@email.com",
				pass:     "p@55w0rd",
				provider: "EMAIL",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := Credential{}

			cred.Create(tt.args.email, tt.args.pass, tt.args.provider)
			assert.NotEmpty(t, cred.ID)
			assert.Equal(t, tt.args.email, cred.Email)
			assert.Equal(t, tt.args.provider, cred.Provider)
			assert.NoError(t, cred.VerifyPassword(tt.args.pass))
		})
	}
}

func TestCredential_GenerateJWT(t *testing.T) {
	tests := []struct {
		name    string
		cred    Credential
		wantErr bool
	}{
		{"ok", Credential{Email: "someone@email.com"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessToken, refreshToken, err := tt.cred.GenerateJWT()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NotEmpty(t, accessToken.Token, "Access token string")
			assert.NotEmpty(t, accessToken.Expiry, "Access token expiry")
			assert.NotEmpty(t, accessToken.CSRFToken, "Access token CSRF token")

			assert.NotEmpty(t, refreshToken.ID, "Refresh token ID")
			assert.NotEmpty(t, refreshToken.Token, "Refresh token string")
			assert.NotEmpty(t, refreshToken.Expiry, "Refresh token expiry")
		})
	}
}
