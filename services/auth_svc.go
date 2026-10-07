package services

import (
	"fmt"
	"sync"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/storage"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

var (
	credsStg         storage.CredsStg
	tokenUpdateLocks map[string]*sync.Mutex
	tokenLocksMux    sync.Mutex
)

func InitCredsSvc() {
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

func GetCredsForRequest(req hm.Request) (creds.Creds, error) {
	currentCreds, ok := credsStg.GetCredsById(req.CredsId)

	if !ok {
		return creds.Creds{}, fmt.Errorf("credentials with id %s not found", req.CredsId)
	}

	if currentCreds.CredsType != constants.CT_OAuth2 {
		return currentCreds, nil
	}

	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in GetCredsById")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds, nil
	}

	tokenLocksMux.Lock()
	mux, ok := tokenUpdateLocks[req.CredsId]
	if !ok {
		mux = &sync.Mutex{}
		tokenUpdateLocks[req.CredsId] = mux
	}
	tokenLocksMux.Unlock()

	mux.Lock()
	defer mux.Unlock()

	currentCreds, _ = credsStg.GetCredsById(req.CredsId)

	oauth2, _ = currentCreds.Creds.(creds.OAuth2Creds)

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds, nil
	}

	refreshOAuthToken(req, currentCreds)

	currentCreds, _ = credsStg.GetCredsById(req.CredsId)
	return currentCreds, nil
}

func refreshOAuthToken(req hm.Request, creds creds.Creds) {

	credsStg.SetCreds(creds.Id, creds)
}
