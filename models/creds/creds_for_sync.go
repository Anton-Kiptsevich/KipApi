package creds

// CredsForSync contains a credential snapshot and the version that must be
// supplied when confirming that snapshot was persisted.
type CredsForSync struct {
	Creds   Creds
	Version uint64
}
