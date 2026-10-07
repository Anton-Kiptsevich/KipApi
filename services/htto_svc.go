package services

import (
	"fmt"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func MakeApiCall(req *hm.Request) (hm.Response, error) {
	if err := InitAuthorizationHeaderIfNeeded(req); err != nil {
		return hm.Response{}, fmt.Errorf("failed to initialize authorization header: %w", err)
	}

	return MakeHttpRequest(req)
}
