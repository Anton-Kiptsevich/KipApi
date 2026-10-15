package services

import (
	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/services/base"
)

func MakeApiCall(call hm.ApiCall) (hm.Response, error) {
	credential, err := GetCredsForRequest(call.CredsId)
	if err != nil {
		return hm.Response{}, err
	}

	if err := utils.ValidateAuthMethod(call.AuthMethod, credential.CredsType); err != nil {
		return hm.Response{}, err
	}

	if credential.CredsType == constants.CT_HMAC {
		hmacCreds, ok := credential.Creds.(creds.HMACCreds)
		if !ok {
			panic("Creds model/type discrepancy")
		}
		if err := utils.ValidateHMACSignatureRequest(hmacCreds.Signature, call.Request); err != nil {
			return hm.Response{}, err
		}
	}

	req, err := InitAuthorizationIfNeeded(call)
	if err != nil {
		return hm.Response{}, err
	}

	return base.MakeHttpRequest(&req)
}
