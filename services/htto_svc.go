package services

import (
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

func MakeApiCall(req hm.Request) (hm.Response, error) {
	creds, err := GetCredsForRequest(req.CredsId)
	if err != nil {
		return hm.Response{}, err
	}

	if err := utils.ValidateAuthMethod(req.AuthMethod, creds.CredsType); err != nil {
		return hm.Response{}, err
	}

	req, err = InitAuthorizationIfNeeded(req)
	if err != nil {
		return hm.Response{}, err
	}

	return MakeHttpRequest(&req)
}
