package services

import (
	"sync"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	"github.com/Anton-Kiptsevich/KipApi/storage"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

var (
	credsStg         storage.CredsStg
	tokenUpdateLocks map[string]*sync.Mutex
	tokenLocksMux    sync.Mutex
)

func InitCredsStg() {
	credsStg = credsStg.InitCredsStg()
	tokenLocksMux.Lock()
	tokenUpdateLocks = make(map[string]*sync.Mutex)
	tokenLocksMux.Unlock()
}

func SetCreds(credsList []creds.Creds) []error {
	errors := make([]error, 0)
	for _, c := range credsList {
		validationError := utils.ValidateCreds(c)
		if validationError != nil {
			errors = append(errors, validationError)
		} else {
			credsStg.SetCreds(c.Id, c)
		}
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func GetAllCreds() map[string]creds.Creds {
	return credsStg.GetAllCreds()
}

func GetCredsById(credsId string) creds.Creds {
	currentCreds := credsStg.GetCredsById(credsId)

	if currentCreds.CredsType != constants.CT_OAuth2 {
		return currentCreds
	}

	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in GetCredsById")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds
	}

	tokenLocksMux.Lock()
	mux, ok := tokenUpdateLocks[credsId]
	if !ok {
		mux = &sync.Mutex{}
		tokenUpdateLocks[credsId] = mux
	}
	tokenLocksMux.Unlock()

	mux.Lock()
	defer mux.Unlock()

	currentCreds = credsStg.GetCredsById(credsId)

	if currentCreds.CredsType != constants.CT_OAuth2 {
		return currentCreds
	}

	oauth2, ok = currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in GetCredsById")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds
	}

	refreshOAuthToken(oauth2)

	return credsStg.GetCredsById(credsId)
}

func refreshOAuthToken(oauth2Creds creds.OAuth2Creds) {
}
