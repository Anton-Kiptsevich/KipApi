package services

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
	auth "github.com/Anton-Kiptsevich/KipApi/services/auth"
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

func SetCreds(credsList []creds.Creds, markAsDirty bool) []error {
	errors := make([]error, 0)
	for _, c := range credsList {
		validationError := utils.ValidateCreds(c.Id, c)
		if validationError != nil {
			errors = append(errors, validationError)
		} else {
			credsStg.SetCreds(c.Id, c, markAsDirty)
		}
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func GetCredsForSync() map[string]creds.Creds {
	return credsStg.GetCredsForSync()
}

func MarkCredsSynced(credsId string) error {
	if !credsStg.MarkCredsSynced(credsId) {
		return fmt.Errorf("credentials with id %s not found", credsId)
	}
	return nil
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
		panic("Creds model/type discrepancy")
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
		panic("Creds model/type discrepancy")
	}

	if !oauth2.ExpirationDate.Before(time.Now().Add(5 * time.Second)) {
		return currentCreds, nil
	}

	updatedCreds, err := auth.RefreshOAuthToken(currentCreds)
	if err != nil {
		return creds.Creds{}, err
	}

	credsStg.SetCreds(currentCreds.Id, updatedCreds, true)
	return updatedCreds, nil
}

func InitAuthorizationIfNeeded(req hm.Request) (hm.Request, error) {
	currentCreds, err := GetCredsForRequest(req.CredsId)
	if err != nil {
		return req, err
	}
	if req.AuthMethod == constants.AM_MTLS {
		if req.TlsCert != nil {
			return req, nil
		}

		mtls, ok := currentCreds.Creds.(creds.MTLSCreds)
		if !ok {
			panic("Auth Method/Creds Type discrepancy")
		}

		cert, err := tls.X509KeyPair(mtls.ClientCert, mtls.ClientKey)
		if err != nil {
			panic("Invalid mtls.ClientCert/mtls.ClientKey pair")
		}

		req.TlsCert = &cert
		return req, nil
	}

	if req.AuthMethod == constants.AM_Query {
		apiKey, ok := currentCreds.Creds.(creds.ApiKeyCreds)
		if !ok {
			panic("Auth Method/Creds Type discrepancy")
		}

		u, err := url.Parse(req.BaseUrl + req.Path)
		if err != nil {
			panic(err)
		}
		q := u.Query()
		if _, exists := q[apiKey.FieldName]; !exists {
			q.Set(apiKey.FieldName, apiKey.ApiKey)
			u.RawQuery = q.Encode()
			req.BaseUrl = u.Scheme + "://" + u.Host
			req.Path = u.RequestURI()
		}

		return req, nil
	}

	headerName := "Authorization"
	headerValue := ""

	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, headerName) {
			return req, nil
		}
	}

	switch req.AuthMethod {
	case constants.AM_Basic:
		basic, ok := currentCreds.Creds.(creds.BasicCreds)
		if !ok {
			panic("Auth Method/Creds Type discrepancy")
		}
		headerValue = "Basic " + base64.StdEncoding.EncodeToString([]byte(basic.Username+":"+basic.Password))

	case constants.AM_Bearer:
		var token string
		switch currentCreds.CredsType {
		case constants.CT_Bearer:
			bearer, ok := currentCreds.Creds.(creds.BearerCreds)
			if !ok {
				panic("Auth Method/Creds Type discrepancy")
			}
			token = bearer.Token
		case constants.CT_OAuth2:
			oauth2, ok := currentCreds.Creds.(creds.OAuth2Creds)
			if !ok {
				panic("Auth Method/Creds Type discrepancy")
			}
			token = oauth2.AccessToken
		default:
			panic("Auth Method/Creds Type discrepancy")
		}
		headerValue = "Bearer " + token

	case constants.AM_Header:
		apiKey, ok := currentCreds.Creds.(creds.ApiKeyCreds)
		if !ok {
			panic("Auth Method/Creds Type discrepancy")
		}
		headerValue = apiKey.ApiKey

	case constants.AM_Digest:
		headerValue, err = auth.GetDigestAuthorization(req, currentCreds)
		if err != nil {
			return req, err
		}
	}

	headers := make([]hm.Header, 0, len(req.Headers)+1)
	headers = append(headers, req.Headers...)
	headers = append(headers, hm.Header{Name: headerName, Value: &headerValue})
	req.Headers = headers

	return req, nil
}
