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
	if stg.MarkCredsSynced("missing") {
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
	if pending := stg.GetCredsForSync(); len(pending) != 1 {
		t.Fatalf("GetCredsForSync() returned %d credentials, want 1", len(pending))
	}
	if !stg.MarkCredsSynced("credential-1") {
		t.Fatal("MarkCredsSynced() returned false for an existing credential")
	}
	if pending := stg.GetCredsForSync(); len(pending) != 0 {
		t.Fatalf("GetCredsForSync() returned %d credentials after sync, want 0", len(pending))
	}

	stg.SetCreds("credential-1", newTestCreds("second"), true)
	pending := stg.GetCredsForSync()
	if len(pending) != 1 || pending["credential-1"].Creds.(creds.BearerCreds).Token != "second" {
		t.Fatalf("updated credential was not marked for sync: %#v", pending)
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
