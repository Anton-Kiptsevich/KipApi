package services

import (
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
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
