package creds

import "time"

type OAuth2Creds struct {
	AccessToken    string
	RefreshToken   string
	ExpirationDate time.Time
}
