package storage

import (
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

func newTestCreds(token string) creds.Creds {
	return creds.Creds{Id: "credential-1", CredsType: constants.CT_Bearer, Creds: creds.BearerCreds{Token: token}}
}

func TestCredsStorageReadAndSyncLifecycle(t *testing.T) {
	var stg CredsStg
	stg = stg.InitCredsStg()
	if _, ok := stg.GetCredsById("missing"); ok {
		t.Fatal("GetCredsById() found a missing credential")
	}
	if stg.MarkCredsSynced("missing", 1) {
		t.Fatal("MarkCredsSynced() succeeded for a missing credential")
	}

	stg.SetCreds("credential-1", newTestCreds("first"), true)
	got, ok := stg.GetCredsById("credential-1")
	if !ok {
		t.Fatal("GetCredsById() did not return the inserted credential")
	}
	if token := got.Creds.(creds.BearerCreds).Token; token != "first" {
		t.Fatalf("stored token = %q, want first", token)
	}

	pending := stg.GetCredsForSync()
	first, ok := pending["credential-1"]
	if len(pending) != 1 || !ok {
		t.Fatalf("GetCredsForSync() returned %#v, want credential-1", pending)
	}
	if token := first.Creds.Creds.(creds.BearerCreds).Token; token != "first" {
		t.Fatalf("pending token = %q, want first", token)
	}
	if !stg.MarkCredsSynced("credential-1", first.Version) {
		t.Fatal("MarkCredsSynced() rejected the current version")
	}
	if pending := stg.GetCredsForSync(); len(pending) != 0 {
		t.Fatalf("GetCredsForSync() returned %d credentials after sync, want 0", len(pending))
	}

	stg.SetCreds("credential-1", newTestCreds("second"), true)
	pending = stg.GetCredsForSync()
	second, ok := pending["credential-1"]
	if len(pending) != 1 || !ok || second.Creds.Creds.(creds.BearerCreds).Token != "second" {
		t.Fatalf("updated credential was not marked for sync: %#v", pending)
	}
}

func TestStaleSyncConfirmationDoesNotClearNewerUpdate(t *testing.T) {
	var stg CredsStg
	stg = stg.InitCredsStg()

	stg.SetCreds("credential-1", newTestCreds("first"), true)
	firstSnapshot := stg.GetCredsForSync()["credential-1"]

	stg.SetCreds("credential-1", newTestCreds("second"), true)
	if stg.MarkCredsSynced("credential-1", firstSnapshot.Version) {
		t.Fatal("MarkCredsSynced() accepted a stale version")
	}

	pending := stg.GetCredsForSync()
	secondSnapshot, ok := pending["credential-1"]
	if len(pending) != 1 || !ok {
		t.Fatalf("newer update disappeared after stale confirmation: %#v", pending)
	}
	if token := secondSnapshot.Creds.Creds.(creds.BearerCreds).Token; token != "second" {
		t.Fatalf("pending token = %q, want second", token)
	}
	if !stg.MarkCredsSynced("credential-1", secondSnapshot.Version) {
		t.Fatal("MarkCredsSynced() rejected the current version")
	}
}

func TestSetCredsCanLoadAlreadySyncedCredential(t *testing.T) {
	var stg CredsStg
	stg = stg.InitCredsStg()
	stg.SetCreds("credential-1", newTestCreds("loaded"), false)
	if pending := stg.GetCredsForSync(); len(pending) != 0 {
		t.Fatalf("loaded credential unexpectedly needs sync: %#v", pending)
	}
}
