package storage

import (
	"sync"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

// CredsForSync contains a credential snapshot and the version that must be
// supplied when confirming that snapshot was persisted.
type CredsForSync struct {
	Creds   creds.Creds
	Version uint64
}

type CredsStg struct {
	credsStg     map[string]creds.Creds
	syncVersions map[string]uint64
	credsMux     sync.RWMutex
}

func (cs *CredsStg) InitCredsStg() CredsStg {
	return CredsStg{
		credsStg:     make(map[string]creds.Creds),
		syncVersions: make(map[string]uint64),
	}
}

func (cs *CredsStg) GetCredsForSync() map[string]CredsForSync {
	cs.credsMux.RLock()
	defer cs.credsMux.RUnlock()

	result := make(map[string]CredsForSync)
	for id, version := range cs.syncVersions {
		// Odd versions are dirty; even versions are clean. Keeping the
		// version after confirmation prevents an old confirmation from
		// matching a later update (an ABA problem).
		if version%2 == 1 {
			result[id] = CredsForSync{
				Creds:   cs.credsStg[id],
				Version: version,
			}
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

	version := cs.syncVersions[credsId]
	if version%2 == 0 {
		// A clean credential becomes dirty.
		version++
	} else {
		// It was already dirty, so invalidate any snapshot already in flight.
		version += 2
	}
	cs.syncVersions[credsId] = version
}

// MarkCredsSynced confirms only the exact version returned by GetCredsForSync.
// It returns false when the credential is missing, already clean, or changed
// after the sync snapshot was taken.
func (cs *CredsStg) MarkCredsSynced(credsId string, version uint64) bool {
	cs.credsMux.Lock()
	defer cs.credsMux.Unlock()

	currentVersion, ok := cs.syncVersions[credsId]
	if !ok || currentVersion != version || currentVersion%2 == 0 {
		return false
	}

	// Advance to an even (clean) version rather than deleting the entry, so
	// future updates never reuse a version from an earlier sync attempt.
	cs.syncVersions[credsId] = currentVersion + 1
	return true
}
