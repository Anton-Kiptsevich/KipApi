package services

import (
	"sync"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	"github.com/Anton-Kiptsevich/KipApi/storage"
)

var (
	credsStg storage.CredsStg
	credsMux sync.RWMutex
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
	credsMux.RLock()
	defer credsMux.RUnlock()

	result := make(map[string]creds.Creds, len(credsStg.GetAllCreds()))
	for id, c := range credsStg.GetAllCreds() {
		result[id] = c
	}

	return result
}

func GetCredsById(credsId string) creds.Creds {
	credsMux.RLock()
	defer credsMux.RUnlock()

	return credsStg.GetCredsById(credsId)
}
