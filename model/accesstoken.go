package model

import "time"

//AccessToken information
type AccessToken struct {
	Token     string
	CSRFToken string
	Expiry    time.Time
}

//RefreshToken information
type RefreshToken struct {
	ID     string
	Token  string
	Expiry time.Time
}
