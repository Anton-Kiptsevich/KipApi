package services

import (
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/services/base"
	"github.com/Anton-Kiptsevich/KipApi/utils"
)

func MakeApiCall(areq hm.AuthorizedRequest) (hm.Response, error) {
	creds, err := GetCredsForRequest(areq.CredsId)
	if err != nil {
		return hm.Response{}, err
	}

	if err := utils.ValidateAuthMethod(areq.AuthMethod, creds.CredsType); err != nil {
		return hm.Response{}, err
	}

	req, err := InitAuthorizationIfNeeded(areq)
	if err != nil {
		return hm.Response{}, err
	}

	return base.MakeHttpRequest(&req)
}
