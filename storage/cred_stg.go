package storage

import (
	"sync"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

type CredsStg struct {
	credsStg map[string]creds.Creds
	credsMux sync.RWMutex
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	return CredsStg{ credsStg : make(map[string]creds.Creds) }
}

func (cs *CredsStg) GetAllCreds() map[string]creds.Creds {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()
	result := make(map[string]creds.Creds, len(cs.credsStg))
	for id, c := range cs.credsStg {
		result[id] = c
	}
	return result
}

func (cs *CredsStg) GetCredsById(credsId string) creds.Creds {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()
	return cs.credsStg[credsId]
}

func (cs *CredsStg) SetCreds(credsId string, creds creds.Creds) {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()
	cs.credsStg[credsId] = creds
}