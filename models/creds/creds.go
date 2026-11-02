package creds

type Creds struct {
	Id        string
	CredsType string
	Creds     any // BasicCreds, BearerCreds, OAuth2Creds, AWSV4Creds, etc...
}
