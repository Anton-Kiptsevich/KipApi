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
	return CredsStg{credsStg: make(map[string]creds.Creds)}
}

func (cs *CredsStg) GetAllCreds() map[string]creds.Creds {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()

	result := make(map[string]creds.Creds, len(cs.credsStg))
	for id, c := range cs.credsStg {
		result[id] = c
	}
	return result
}

func (cs *CredsStg) GetCredsById(credsId string) (creds.Creds, bool) {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()
	c, ok := cs.credsStg[credsId]
	return c, ok
}

func (cs *CredsStg) SetCreds(credsId string, creds creds.Creds) {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	cs.credsStg[credsId] = creds
}
