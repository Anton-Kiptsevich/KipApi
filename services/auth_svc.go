package services

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		validationError := utils.ValidateCreds(c.Id, c)
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

func GetCredsForRequest(credsId string) (creds.Creds, error) {
	currentCreds, ok := credsStg.GetCredsById(credsId)

	if !ok {
		return creds.Creds{}, fmt.Errorf("credentials with id %s not found", credsId)
	}

	if currentCreds.CredsType != constants.CT_OAuth2 {
		return currentCreds, nil
	}

	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in GetCredsForRequest")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds, nil
	}

	tokenLocksMux.Lock()
	mux, ok := tokenUpdateLocks[credsId]
	if !ok {
		mux = &sync.Mutex{}
		tokenUpdateLocks[credsId] = mux
	}
	tokenLocksMux.Unlock()

	mux.Lock()
	defer mux.Unlock()

	currentCreds, _ = credsStg.GetCredsById(credsId)

	oauth2, ok = currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in GetCredsForRequest")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds, nil
	}

	if err := refreshOAuthToken(currentCreds); err != nil {
		return creds.Creds{}, err
	}

	currentCreds, _ = credsStg.GetCredsById(credsId)
	return currentCreds, nil
}

func refreshOAuthToken(currentCreds creds.Creds) error {
	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		panic("Smth is wrong in refreshOAuthToken")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", oauth2.RefreshToken)
	form.Set("client_id", oauth2.ClientID)
	form.Set("client_secret", oauth2.ClientSecret)
	contentType := "application/x-www-form-urlencoded"

	req := hm.Request{
		Method:  http.MethodPost,
		BaseUrl: oauth2.TokenURL,
		Headers: []hm.Header{{
			Name:  "Content-Type",
			Value: &contentType,
		}},
		Body: form.Encode(),
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