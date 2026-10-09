package storage

import (
	"sync"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

type credsSyncState struct {
	lastUpdatedAt time.Time
	lastSyncedAt  time.Time
}

type CredsStg struct {
	credsStg map[string]creds.Creds
	syncStg  map[string]credsSyncState
	credsMux sync.RWMutex
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	return CredsStg{
		credsStg: make(map[string]creds.Creds),
		syncStg:  make(map[string]credsSyncState),
	}
}

func (cs *CredsStg) GetCredsForSync() map[string]creds.Creds {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()

	result := make(map[string]creds.Creds)
	for id, state := range cs.syncStg {
		if state.lastUpdatedAt.After(state.lastSyncedAt) {
			result[id] = cs.credsStg[id]
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

func (cs *CredsStg) SetCreds(credsId string, c creds.Creds, markAsDirty bool) {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	now := time.Now()
	cs.credsStg[credsId] = c

	state, exists := cs.syncStg[credsId]
	if !exists {
		state.lastUpdatedAt = now
		if markAsDirty {
			state.lastSyncedAt = time.Time{}
		} else {
			state.lastSyncedAt = now
		}
	} else if markAsDirty {
		state.lastUpdatedAt = now
	}

	cs.syncStg[credsId] = state
}

func (cs *CredsStg) MarkCredsSynced(credsId string) bool {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	state, ok := cs.syncStg[credsId]
	if !ok {
		return false
	}

	state.lastSyncedAt = state.lastUpdatedAt
	cs.syncStg[credsId] = state
	return true
}
