package storage

import "github.com/Anton-Kiptsevich/KipApi/models/creds"

var credsStg = make(map[string]creds.Creds)

func getAllCreds() map[string]creds.Creds {
	return credsStg
}