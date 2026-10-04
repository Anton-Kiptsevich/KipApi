package creds

type Creds struct {
	CredsType string
	Creds     any // BasicCreds, BearerCreds, OAuth2Creds, etc...
}