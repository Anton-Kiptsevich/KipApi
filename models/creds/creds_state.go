package creds

import "time"

type CredsState struct {
	Creds        Creds
	LastUpdatedAt time.Time
	LastSyncedAt  time.Time
}
