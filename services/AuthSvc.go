package services

import (
	"sync"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	"github.com/Anton-Kiptsevich/KipApi/storage"
)

var (
	credsStg storage.CredsStg
	credsMux sync.Mutex
)

func InitCredsStg() {
	credsMux.Lock()
	defer credsMux.Unlock()

	credsStg = credsStg.InitCredsStg()
}

func SetCreds(credsList []creds.Creds) {
	credsMux.Lock()
	defer credsMux.Unlock()

	for _, c := range credsList {
		credsStg.SetCreds(c.Id, c)
	}
}

func GetAllCreds() map[string]creds.Creds {
	credsMux.Lock()
	defer credsMux.Unlock()

	return credsStg.GetAllCreds()
}

func GetCredsById(credsId string) creds.Creds {
	credsMux.Lock()
	defer credsMux.Unlock()

	return credsStg.GetCredsById(credsId)
}
