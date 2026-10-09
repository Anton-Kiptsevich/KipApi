package services

import (
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/services/base"
	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
)

func MakeApiCall(call hm.ApiCall) (hm.Response, error) {
	creds, err := GetCredsForRequest(call.CredsId)
	if err != nil {
		return hm.Response{}, err
	}

	if err := utils.ValidateAuthMethod(call.AuthMethod, creds.CredsType); err != nil {
		return hm.Response{}, err
	}

	req, err := InitAuthorizationIfNeeded(call)
	if err != nil {
		return hm.Response{}, err
	}

	return base.MakeHttpRequest(&req)
}
