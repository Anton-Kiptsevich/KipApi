package services

import (
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	"github.com/Anton-Kiptsevich/KipApi/storage"
)

var (
	credsStg storage.CredsStg
)

func InitCredsStg() {
	credsStg = credsStg.InitCredsStg()
}

func SetCreds(credsList []creds.Creds) {
	for _, c := range credsList {
		credsStg.SetCreds(c.Id, c)
	}
}

func GetAllCreds() map[string]creds.Creds {
	return credsStg.GetAllCreds()
}

func GetCredsById(credsId string) creds.Creds {
	return credsStg.GetCredsById(credsId)
}
