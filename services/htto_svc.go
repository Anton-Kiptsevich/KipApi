package services

import (
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func MakeApiCall(req hm.Request) (hm.Response, error) {
	req, err := InitAuthorizationHeaderIfNeeded(req)
	if err != nil {
		return hm.Response{}, err
	}

	return MakeHttpRequest(&req)
}
