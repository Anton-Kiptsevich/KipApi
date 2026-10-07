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
	credsStg storage.CredsStg
	tokenUpdateLocks map[string]sync.Mutex
)

func InitCredsStg() {
	credsStg = credsStg.InitCredsStg()
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
	creds := credsStg.GetCredsById(credsId)
	if creds.CredsType == constants.CT_OAuth2 {
		oauth2, ok := creds.Creds.(creds.OAuth2Creds)
		if !ok {
			panic("Smth is wrong in GetCredsById")
		}
		if oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
			if _, ok := tokenUpdateLocks[creds.Id]; !ok {
				tokenUpdateLocks[creds.Id] = sync.Mutex{}
			}
			mux := tokenUpdateLocks[creds.Id]
			mux.Lock()
			refreshOAuthToken(oauth2)
			mux.Unlock()
		}

	}
	return credsStg.GetCredsById(credsId)
}

func refreshOAuthToken(oauth2Creds creds.Creds) {
	
}