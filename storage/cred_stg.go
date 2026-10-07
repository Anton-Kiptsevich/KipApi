package storage

import "github.com/Anton-Kiptsevich/KipApi/models/creds"

type CredsStg struct {
	credsStg map[string]creds.Creds
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	return CredsStg{ credsStg : make(map[string]creds.Creds) }
}

func (cs *CredsStg) GetAllCreds() map[string]creds.Creds {
	return cs.credsStg
}

func (cs *CredsStg) GetCredsById(credsId string) creds.Creds {
	return cs.credsStg[credsId]
}

func (cs *CredsStg) SetCreds(credsId string, creds creds.Creds) {
	cs.credsStg[credsId] = creds
}