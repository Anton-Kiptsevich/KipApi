package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestApiKeyHeaderUsesConfiguredFieldName(t *testing.T) {
	InitCredsSvc()

	credential := creds.Creds{
		Id:        "test-api-key",
		CredsType: constants.CT_ApiKey,
		Creds: creds.ApiKeyCreds{
			ApiKey:    "secret-value",
			FieldName: "X-API-Key",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_Header,
		Request: hm.Request{
			Method:  "GET",
			BaseUrl: "https://api.example.com",
			Path:    "/users",
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(request.Headers))
	}
	if request.Headers[0].Name != "X-API-Key" {
		t.Fatalf("header name = %q, want %q", request.Headers[0].Name, "X-API-Key")
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != "secret-value" {
		t.Fatalf("header value = %v, want %q", request.Headers[0].Value, "secret-value")
	}
}

func TestApiKeyHeaderPreservesExistingConfiguredHeader(t *testing.T) {
	InitCredsSvc()

	credential := creds.Creds{
		Id:        "test-api-key-existing",
		CredsType: constants.CT_ApiKey,
		Creds: creds.ApiKeyCreds{
			ApiKey:    "secret-value",
			FieldName: "X-API-Key",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	existingValue := "provided-by-caller"
	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_Header,
		Request: hm.Request{
			Method:  "GET",
			BaseUrl: "https://api.example.com",
			Path:    "/users",
			Headers: []hm.Header{{Name: "x-api-key", Value: &existingValue}},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(request.Headers))
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != existingValue {
		t.Fatalf("existing header value changed")
	}
}

func TestInitAuthorizationIfNeededBasicAuth(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "basic-auth-unit",
		CredsType: constants.CT_Basic,
		Creds:     creds.BasicCreds{Username: "user", Password: "pass"},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Basic,
		Request: hm.Request{Method: "GET", BaseUrl: "https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 || request.Headers[0].Name != "Authorization" {
		t.Fatalf("headers = %#v, want one Authorization header", request.Headers)
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != "Basic dXNlcjpwYXNz" {
		t.Errorf("Authorization = %v, want Basic dXNlcjpwYXNz", request.Headers[0].Value)
	}
}

func TestInitAuthorizationIfNeededBearerAuthAddsStoredToken(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "bearer-auth-add-unit",
		CredsType: constants.CT_Bearer,
		Creds:     creds.BearerCreds{Token: "stored-token"},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Bearer,
		Request: hm.Request{Method: "GET", BaseUrl: "https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 || request.Headers[0].Name != "Authorization" {
		t.Fatalf("headers = %#v, want one Authorization header", request.Headers)
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != "Bearer stored-token" {
		t.Errorf("Authorization = %v, want Bearer stored-token", request.Headers[0].Value)
	}
}

func TestInitAuthorizationIfNeededBearerAuthPreservesCallerHeader(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "bearer-auth-unit",
		CredsType: constants.CT_Bearer,
		Creds:     creds.BearerCreds{Token: "stored-token"},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	callerAuthorization := "caller-authorization"
	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Bearer,
		Request: hm.Request{
			Method: "GET", BaseUrl: "https://api.example.com",
			Headers: []hm.Header{{Name: "authorization", Value: &callerAuthorization}},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(request.Headers))
	}
	if request.Headers[0].Value != &callerAuthorization || *request.Headers[0].Value != callerAuthorization {
		t.Error("caller-provided Authorization header was overwritten")
	}
}

func TestInitAuthorizationIfNeededOAuth2BearerAuth(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "oauth2-bearer-auth-unit",
		CredsType: constants.CT_OAuth2,
		Creds: creds.OAuth2Creds{
			AccessToken: "oauth-access-token", RefreshToken: "oauth-refresh-token",
			ExpirationDate: time.Now().Add(time.Hour), TokenURL: "https://api.example.com/token",
			ClientID: "client", ClientSecret: "secret",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Bearer,
		Request: hm.Request{Method: "GET", BaseUrl: "https://api.example.com"},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Headers) != 1 || request.Headers[0].Name != "Authorization" {
		t.Fatalf("headers = %#v, want one Authorization header", request.Headers)
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != "Bearer oauth-access-token" {
		t.Errorf("Authorization = %v, want Bearer oauth-access-token", request.Headers[0].Value)
	}
}

func TestInitAuthorizationIfNeededQueryAuth(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "query-auth-unit",
		CredsType: constants.CT_ApiKey,
		Creds:     creds.ApiKeyCreds{ApiKey: "secret value", FieldName: "api_key"},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Query,
		Request: hm.Request{
			Method: "GET", BaseUrl: "https://api.example.com",
			Path: "/resource?existing=1",
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if request.BaseUrl != "https://api.example.com" {
		t.Errorf("BaseUrl = %q, want https://api.example.com", request.BaseUrl)
	}
	if request.Path != "/resource?api_key=secret+value&existing=1" {
		t.Errorf("Path = %q, want /resource?api_key=secret+value&existing=1", request.Path)
	}
	if len(request.Headers) != 0 {
		t.Errorf("query auth unexpectedly added headers: %#v", request.Headers)
	}
}

func TestInitAuthorizationIfNeededQueryAuthPreservesExistingKey(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "query-auth-existing-unit",
		CredsType: constants.CT_ApiKey,
		Creds:     creds.ApiKeyCreds{ApiKey: "stored-secret", FieldName: "api_key"},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Query,
		Request: hm.Request{
			Method: "GET", BaseUrl: "https://api.example.com",
			Path: "/resource?api_key=caller-value&existing=1",
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if request.Path != "/resource?api_key=caller-value&existing=1" {
		t.Errorf("Path = %q, want existing api_key value to be preserved", request.Path)
	}
}

func TestInitAuthorizationIfNeededCookieAuthPreservesExistingCookie(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "cookie-auth-unit",
		CredsType: constants.CT_Cookie,
		Creds: creds.CookieCreds{Cookies: []hm.Cookie{
			{Name: "session", Value: "stored-session"},
			{Name: "refresh", Value: "stored-refresh"},
		}},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	callerCookie := hm.Cookie{Name: "SESSION", Value: "caller-session"}
	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Cookie,
		Request: hm.Request{
			Method: "GET", BaseUrl: "https://api.example.com",
			Cookies: []hm.Cookie{callerCookie},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	if len(request.Cookies) != 2 {
		t.Fatalf("got %d cookies, want 2", len(request.Cookies))
	}
	if request.Cookies[0] != callerCookie {
		t.Errorf("existing cookie = %#v, want %#v", request.Cookies[0], callerCookie)
	}
	if request.Cookies[1] != (hm.Cookie{Name: "refresh", Value: "stored-refresh"}) {
		t.Errorf("added cookie = %#v, want stored refresh cookie", request.Cookies[1])
	}
}

func TestInitAuthorizationIfNeededHMACAuth(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{
		Id:        "hmac-auth-unit",
		CredsType: constants.CT_HMAC,
		Creds: creds.HMACCreds{
			Algorithm: constants.HA_SHA256, SecretKey: "secret",
			SignatureEncoding: "hex", SignatureHeaderName: "X-Signature",
			Signature: "{method}|{path}",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_HMAC,
		Request: hm.Request{Method: "GET", BaseUrl: "https://api.example.com", Path: "/resource"},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}

	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write([]byte("GET|/resource"))
	wantSignature := hex.EncodeToString(mac.Sum(nil))
	if len(request.Headers) != 1 || request.Headers[0].Name != "X-Signature" {
		t.Fatalf("headers = %#v, want one X-Signature header", request.Headers)
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != wantSignature {
		t.Errorf("X-Signature = %v, want %q", request.Headers[0].Value, wantSignature)
	}
}

func TestAWSV4AuthorizationHeaders(t *testing.T) {
	InitCredsSvc()

	credential := creds.Creds{
		Id:        "aws-v4-unit",
		CredsType: constants.CT_AWS,
		Creds: creds.AWSV4Creds{
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "host",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const date = "Mon, 09 Sep 2011 23:36:00 GMT"
	dateValue := date
	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_AWS,
		Request: hm.Request{
			Method:  "GET",
			BaseUrl: "https://host.foo.com",
			Path:    "/",
			Headers: []hm.Header{{Name: "Date", Value: &dateValue}},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}

	if len(request.Headers) != 3 {
		t.Fatalf("got %d headers, want 3", len(request.Headers))
	}
	for _, name := range []string{"Authorization", "X-Amz-Content-Sha256", "X-Amz-Date"} {
		if count := awsV4HeaderCount(request.Headers, name); count != 1 {
			t.Errorf("%s header count = %d, want 1", name, count)
		}
	}
	headerValues := awsV4HeaderValues(request.Headers)
	const wantAuthorization = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=8669346105352fcd40f85d6d892aed321806bbc8c65a5aa324eb6cbc4f974838"
	if got := headerValues["authorization"]; got != wantAuthorization {
		t.Errorf("Authorization = %q, want %q", got, wantAuthorization)
	}
	if got := headerValues["x-amz-content-sha256"]; got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("X-Amz-Content-Sha256 = %q, want SHA-256 of empty payload", got)
	}
	if got := headerValues["x-amz-date"]; got != "20110909T233600Z" {
		t.Errorf("X-Amz-Date = %q, want 20110909T233600Z", got)
	}
}

func TestAWSV4AuthorizationOverwritesExistingHeadersWhenDateExists(t *testing.T) {
	InitCredsSvc()

	credential := creds.Creds{
		Id:        "aws-v4-overwrite-existing-date",
		CredsType: constants.CT_AWS,
		Creds: creds.AWSV4Creds{
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
			Service:         "host",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const existingDate = "20110909T233600Z"
	const dateHeader = "Mon, 09 Sep 2011 23:36:00 GMT"
	const payloadHashValue = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	existingAuthorization := "caller-authorization"
	existingPayloadHash := payloadHashValue
	existingDateHeader := dateHeader
	existingDateValue := existingDate

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_AWS,
		Request: hm.Request{
			Method:  "GET",
			BaseUrl: "https://host.foo.com",
			Path:    "/",
			Headers: []hm.Header{
				{Name: "Authorization", Value: &existingAuthorization},
				{Name: "X-Amz-Content-Sha256", Value: &existingPayloadHash},
				{Name: "X-Amz-Date", Value: &existingDateValue},
				{Name: "Date", Value: &existingDateHeader},
			},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}

	if len(request.Headers) != 4 {
		t.Fatalf("got %d headers, want 4", len(request.Headers))
	}
	const wantAuthorization = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=8669346105352fcd40f85d6d892aed321806bbc8c65a5aa324eb6cbc4f974838"
	if request.Headers[0].Value == nil || *request.Headers[0].Value != wantAuthorization {
		t.Errorf("Authorization = %v, want %q", request.Headers[0].Value, wantAuthorization)
	}
	if request.Headers[0].Value == &existingAuthorization {
		t.Error("existing Authorization header was not replaced")
	}
	if request.Headers[1].Value == nil || *request.Headers[1].Value != payloadHashValue {
		t.Errorf("X-Amz-Content-Sha256 = %v, want %q", request.Headers[1].Value, payloadHashValue)
	}
	if request.Headers[1].Value == &existingPayloadHash {
		t.Error("existing X-Amz-Content-Sha256 header was not replaced")
	}
	if request.Headers[2].Value != &existingDateValue || *request.Headers[2].Value != existingDate {
		t.Error("existing X-Amz-Date header was modified")
	}
	if request.Headers[3].Value != &existingDateHeader || *request.Headers[3].Value != dateHeader {
		t.Error("existing Date header was modified")
	}
}

func TestAWSV4AuthorizationPreservesExistingHeadersWithoutDate(t *testing.T) {
	InitCredsSvc()

	credential := awsV4TestCreds("aws-v4-preserve-without-date")
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const body = "payload"
	before := time.Now().UTC()
	payloadHash := sha256.Sum256([]byte(body))
	payloadHashValue := hex.EncodeToString(payloadHash[:])
	existingAuthorization := "caller-authorization"
	existingPayloadHash := payloadHashValue

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_AWS,
		Request: hm.Request{
			Method:  "POST",
			BaseUrl: "https://api.example.com",
			Path:    "/resource",
			Body:    body,
			Headers: []hm.Header{
				{Name: "Authorization", Value: &existingAuthorization},
				{Name: "X-Amz-Content-Sha256", Value: &existingPayloadHash},
			},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}
	after := time.Now().UTC()

	if len(request.Headers) != 3 {
		t.Fatalf("got %d headers, want 3", len(request.Headers))
	}

	if request.Headers[0].Name != "Authorization" || request.Headers[1].Name != "X-Amz-Content-Sha256" {
		t.Fatalf("existing headers changed order or names: %#v", request.Headers[:2])
	}
	if request.Headers[0].Value != &existingAuthorization || *request.Headers[0].Value != existingAuthorization {
		t.Error("existing Authorization header was overwritten")
	}
	if request.Headers[1].Value != &existingPayloadHash || *request.Headers[1].Value != payloadHashValue {
		t.Error("existing X-Amz-Content-Sha256 header was overwritten")
	}
	if !strings.EqualFold(request.Headers[2].Name, "X-Amz-Date") {
		t.Errorf("third header name = %q, want X-Amz-Date", request.Headers[2].Name)
	}
	if request.Headers[2].Value == nil {
		t.Fatal("generated X-Amz-Date header has nil value")
	}
	generatedDate, err := time.Parse(utils.GetTimeFormatPattern(), *request.Headers[2].Value)
	if err != nil {
		t.Errorf("generated X-Amz-Date has invalid format: %v", err)
	} else if generatedDate.Before(before) || generatedDate.After(after) {
		t.Errorf("generated X-Amz-Date = %v, want a time between %v and %v", generatedDate, before, after)
	}
}

func awsV4TestCreds(id string) creds.Creds {
	return creds.Creds{
		Id:        id,
		CredsType: constants.CT_AWS,
		Creds: creds.AWSV4Creds{
			AccessKeyID:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Region:          "us-east-1",
			Service:         "execute-api",
		},
	}
}

func awsV4HeaderCount(headers []hm.Header, name string) int {
	count := 0
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			count++
		}
	}
	return count
}

func awsV4HeaderValues(headers []hm.Header) map[string]string {
	values := make(map[string]string, len(headers))
	for _, header := range headers {
		if header.Value != nil {
			values[strings.ToLower(header.Name)] = *header.Value
		}
	}
	return values
}
