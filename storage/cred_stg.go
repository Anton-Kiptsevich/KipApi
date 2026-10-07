package storage

import (
	"sync"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

type CredsStg struct {
	credsStg map[string]creds.Creds
	stateStg map[string]creds.CredsState
	credsMux sync.RWMutex
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	return CredsStg{
		credsStg: make(map[string]creds.Creds),
		stateStg: make(map[string]creds.CredsState),
	}
}

func (cs *CredsStg) GetCredsForSync() map[string]creds.CredsState {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()

	result := make(map[string]creds.CredsState)
	for id, state := range cs.stateStg {
		if state.LastUpdatedAt.After(state.LastSyncedAt) {
			result[id] = state
		}
	}
	return result
}

func (cs *CredsStg) GetCredsById(credsId string) (creds.Creds, bool) {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()

	c, ok := cs.credsStg[credsId]
	return c, ok
}

func (cs *CredsStg) SetCreds(credsId string, c creds.Creds) {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	now := time.Now()
	cs.credsStg[credsId] = c
	cs.stateStg[credsId] = creds.CredsState{
		Creds:        c,
		LastUpdatedAt: now,
		LastSyncedAt:  now,
	}
}

func (cs *CredsStg) UpdateCreds(credsId string, c creds.Creds) {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	state := cs.stateStg[credsId]
	state.Creds = c
	state.LastUpdatedAt = time.Now()
	cs.credsStg[credsId] = c
	cs.stateStg[credsId] = state
}

func (cs *CredsStg) MarkCredsSynced(credsId string, syncedAt time.Time) bool {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	state, ok := cs.stateStg[credsId]
	if !ok || syncedAt.After(state.LastUpdatedAt) {
		return false
	}

	if syncedAt.After(state.LastSyncedAt) {
		state.LastSyncedAt = syncedAt
		cs.stateStg[credsId] = state
	}
	return true
}
