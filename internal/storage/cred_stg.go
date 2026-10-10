package storage

import (
	"sync"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

type syncState struct {
	version         uint64
	isSyncInProcess bool
}

type CredsStg struct {
	credsStg     map[string]creds.Creds
	syncVersions map[string]syncState
	credsMux     sync.RWMutex
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	return CredsStg{
		credsStg:     make(map[string]creds.Creds),
		syncVersions: make(map[string]syncState),
	}
}

// GetCredsForSync returns dirty credentials that are not already being synced
// and marks each returned credential as having a sync in progress.
func (cs *CredsStg) GetCredsForSync() map[string]creds.CredsForSync {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	result := make(map[string]creds.CredsForSync)
	for id, state := range cs.syncVersions {
		if state.isSyncInProcess {
			continue
		}

		state.isSyncInProcess = true
		cs.syncVersions[id] = state
		result[id] = creds.CredsForSync{
			Creds:   cs.credsStg[id],
			Version: state.version,
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

	cs.credsStg[credsId] = c
	if !markAsDirty {
		return
	}

	state := cs.syncVersions[credsId]
	state.version++
	state.isSyncInProcess = false
	cs.syncVersions[credsId] = state
}

// MarkCredsSynced removes sync state only when the confirmed snapshot is still
// current and a sync for that version is marked as in progress.
func (cs *CredsStg) MarkCredsSynced(credsId string, version uint64) bool {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	state, ok := cs.syncVersions[credsId]
	if !ok || state.version != version || !state.isSyncInProcess {
		return false
	}

	delete(cs.syncVersions, credsId)
	return true
}
