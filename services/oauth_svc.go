package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func refreshOAuthToken(currentCreds creds.Creds) (creds.Creds, error) {
	oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
	if !ok {
		return creds.Creds{}, fmt.Errorf("credentials with id %s are not OAuth2 credentials", currentCreds.Id)
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", oauth2.RefreshToken)
	form.Set("client_id", oauth2.ClientID)
	form.Set("client_secret", oauth2.ClientSecret)

	res, err := makeOAuthTokenRequest(oauth2.TokenURL, form)
	if err != nil {
		return creds.Creds{}, fmt.Errorf("failed to refresh OAuth2 token: %w", err)
	}

	parsed, err := parseTokenResponse(res, "OAuth2 token refresh")
	if err != nil {
		return creds.Creds{}, err
	}

	if parsed.RefreshToken == "" {
		parsed.RefreshToken = oauth2.RefreshToken
	}

	oauth2.AccessToken = parsed.AccessToken
	oauth2.RefreshToken = parsed.RefreshToken
	oauth2.ExpirationDate = time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second)

	return creds.Creds{
		Id:        currentCreds.Id,
		CredsType: currentCreds.CredsType,
		Creds:     oauth2,
	}, nil
}

func GetOAuthTokenByPassword(
	tokenURL string,
	clientID string,
	clientSecret string,
	username string,
	password string,
) (creds.OAuth2Creds, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)

	res, err := makeOAuthTokenRequest(tokenURL, form)
	if err != nil {
		return creds.OAuth2Creds{}, fmt.Errorf("failed to get OAuth2 token: %w", err)
	}

	parsed, err := parseTokenResponse(res, "OAuth2 token request")
	if err != nil {
		return creds.OAuth2Creds{}, err
	}

	return creds.OAuth2Creds{
		AccessToken:    parsed.AccessToken,
		RefreshToken:   parsed.RefreshToken,
		ExpirationDate: time.Now().Add(time.Duration(parsed.ExpiresIn) * time.Second),
		TokenURL:       tokenURL,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
	}, nil
}

func makeOAuthTokenRequest(tokenURL string, form url.Values) (hm.Response, error) {
	contentType := "application/x-www-form-urlencoded"
	req := hm.Request{
		Method:  http.MethodPost,
		BaseUrl: tokenURL,
		Headers: []hm.Header{{
			Name:  "Content-Type",
			Value: &contentType,
		}},
		Body: form.Encode(),
	}

	return MakeHttpRequest(&req)
}

func parseTokenResponse(res hm.Response, operation string) (tokenResponse, error) {
	statusParts := strings.Fields(res.Status)
	if len(statusParts) == 0 {
		return tokenResponse{}, fmt.Errorf("%s returned empty response status", operation)
	}

	statusCode, err := strconv.Atoi(statusParts[0])
	if err != nil {
		return tokenResponse{}, fmt.Errorf("failed to parse %s response status %q: %w", operation, res.Status, err)
	}

	if statusCode < 200 || statusCode >= 300 {
		return tokenResponse{}, fmt.Errorf("%s failed with status %s: %s", operation, res.Status, res.Body)
	}

	var result tokenResponse
	if err := json.Unmarshal([]byte(res.Body), &result); err != nil {
		return tokenResponse{}, fmt.Errorf("failed to parse %s: %w", operation, err)
	}

	if result.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("%s does not contain access_token", operation)
	}

	if result.ExpiresIn <= 0 {
		return tokenResponse{}, fmt.Errorf("%s does not contain valid expires_in", operation)
	}

	return result, nil
}
