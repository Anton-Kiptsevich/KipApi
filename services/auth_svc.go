package services

import (
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	"github.com/Anton-Kiptsevich/KipApi/storage"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

var (
	credsStg storage.CredsStg
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
	return credsStg.GetCredsById(credsId)
}

func refreshOAuthToken() {

}