package services

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
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

	err := refreshOAuthToken(req, currentCreds)
	if err != nil {
		return creds.Creds{}, err
	}

	currentCreds, _ = credsStg.GetCredsById(req.CredsId)
	return currentCreds, nil
}

func refreshOAuthToken(req hm.Request, currentCreds creds.Creds) error {
	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in refreshOAuthToken")
	}

	form, err := url.ParseQuery(req.Body)
	if err != nil {
		return fmt.Errorf("failed to parse OAuth2 refresh request body: %w", err)
	}

	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", oauth2.RefreshToken)

	req.Body = form.Encode()

	contentTypeSet := false
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			contentTypeSet = true
			break
		}
	}

	if !contentTypeSet {
		contentType := "application/x-www-form-urlencoded"
		req.Headers = append(req.Headers, hm.Header{
			Name:  "Content-Type",
			Value: &contentType,
		})
	}

	res, err := MakeHttpRequest(&req)
	if err != nil {
		return fmt.Errorf("failed to refresh OAuth2 token: %w", err)
	}

	statusParts := strings.Fields(res.Status)
	if len(statusParts) == 0 {
		return fmt.Errorf("OAuth2 token refresh returned empty response status")
	}

	statusCode, err := strconv.Atoi(statusParts[0])
	if err != nil {
		return fmt.Errorf("failed to parse OAuth2 token response status %q: %w", res.Status, err)
	}

	if statusCode < 200 || statusCode >= 300 {
		return fmt.Errorf("OAuth2 token refresh failed with status %s: %s", res.Status, res.Body)
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	if err := json.Unmarshal([]byte(res.Body), &tokenResponse); err != nil {
		return fmt.Errorf("failed to parse OAuth2 token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return fmt.Errorf("OAuth2 token response does not contain access_token")
	}

	if tokenResponse.ExpiresIn <= 0 {
		return fmt.Errorf("OAuth2 token response does not contain valid expires_in")
	}

	if tokenResponse.RefreshToken == "" {
		tokenResponse.RefreshToken = oauth2.RefreshToken
	}

	oauth2.AccessToken = tokenResponse.AccessToken
	oauth2.RefreshToken = tokenResponse.RefreshToken
	oauth2.ExpirationDate = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)

	credsStg.SetCreds(currentCreds.Id, creds.Creds{
		Id:        currentCreds.Id,
		CredsType: currentCreds.CredsType,
		Creds:     oauth2,
	})

	return nil
}
