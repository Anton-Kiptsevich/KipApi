package services

import (
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

func TestAWSV4AuthorizationHeaders(t *testing.T) {
	InitCredsSvc()

	credential := creds.Creds{
		Id:        "aws-v4-unit",
		CredsType: constants.CT_AWS,
		Creds: creds.AWSV4Creds{
			AccessKeyID:     "test-access-key",
			SecretAccessKey: "test-secret-key",
			Region:          "us-east-1",
			Service:         "execute-api",
		},
	}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const body = `{"message":"hello"}`
	const requestDate = "20261106T090000Z"
	contentType := "application/json"
	date := requestDate

	request, err := InitAuthorizationIfNeeded(hm.ApiCall{
		CredsId:    credential.Id,
		AuthMethod: constants.AM_AWS,
		Request: hm.Request{
			Method:  "POST",
			BaseUrl: "https://api.example.com",
			Path:    "/resource?z=last&a=first",
			Body:    body,
			Headers: []hm.Header{
				{Name: "Content-Type", Value: &contentType},
				{Name: "X-Amz-Date", Value: &date},
			},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}

	headerValues := make(map[string]string, len(request.Headers))
	for _, header := range request.Headers {
		if header.Value != nil {
			headerValues[strings.ToLower(header.Name)] = *header.Value
		}
	}

	payloadHash := sha256.Sum256([]byte(body))
	expectedPayloadHash := hex.EncodeToString(payloadHash[:])
	if got := headerValues["x-amz-content-sha256"]; got != expectedPayloadHash {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", got, expectedPayloadHash)
	}

	const authorizationPrefix = "AWS4-HMAC-SHA256 Credential=test-access-key/20261106/us-east-1/execute-api/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature="
	authorization := headerValues["authorization"]
	if !strings.HasPrefix(authorization, authorizationPrefix) {
		t.Fatalf("Authorization = %q, want prefix %q", authorization, authorizationPrefix)
	}

	signature := strings.TrimPrefix(authorization, authorizationPrefix)
	if len(signature) != 64 {
		t.Errorf("AWS4 signature length = %d, want 64", len(signature))
	}
	if _, err := hex.DecodeString(signature); err != nil {
		t.Errorf("AWS4 signature is not hexadecimal: %v", err)
	}
}

func TestAWSV4AuthorizationOverwritesExistingHeadersWhenDateExists(t *testing.T) {
	InitCredsSvc()

	credential := awsV4TestCreds("aws-v4-overwrite-existing-date")
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const body = "payload"
	payloadHash := sha256.Sum256([]byte(body))
	payloadHashValue := hex.EncodeToString(payloadHash[:])
	existingAuthorization := "caller-authorization"
	existingPayloadHash := payloadHashValue
	existingDate := "20261106T090000Z"

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
				{Name: "X-Amz-Date", Value: &existingDate},
			},
		},
	})
	if err != nil {
		t.Fatalf("InitAuthorizationIfNeeded() error = %v", err)
	}

	headerValues := awsV4HeaderValues(request.Headers)
	if headerValues["authorization"] == existingAuthorization {
		t.Error("existing Authorization header was not replaced")
	}
	if headerValues["x-amz-content-sha256"] != payloadHashValue {
		t.Errorf("X-Amz-Content-Sha256 = %q, want %q", headerValues["x-amz-content-sha256"], payloadHashValue)
	}
	if headerValues["x-amz-date"] != existingDate {
		t.Errorf("X-Amz-Date = %q, want existing value %q", headerValues["x-amz-date"], existingDate)
	}
	if len(request.Headers) != 3 {
		t.Errorf("got %d headers, want 3", len(request.Headers))
	}
}

func TestAWSV4AuthorizationPreservesExistingHeadersWithoutDate(t *testing.T) {
	InitCredsSvc()

	credential := awsV4TestCreds("aws-v4-preserve-without-date")
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		t.Fatalf("SetCreds() errors = %v", errs)
	}

	const body = "payload"
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

	headerValues := awsV4HeaderValues(request.Headers)
	if headerValues["authorization"] != existingAuthorization {
		t.Errorf("Authorization = %q, want existing value %q", headerValues["authorization"], existingAuthorization)
	}
	if headerValues["x-amz-content-sha256"] != payloadHashValue {
		t.Errorf("X-Amz-Content-Sha256 = %q, want existing value %q", headerValues["x-amz-content-sha256"], payloadHashValue)
	}
	if _, exists := headerValues["x-amz-date"]; !exists {
		t.Error("generated X-Amz-Date header is missing")
	}
	if _, err := time.Parse(utils.GetTimeFormatPattern(), headerValues["x-amz-date"]); err != nil {
		t.Errorf("generated X-Amz-Date has invalid format: %v", err)
	}
	if len(request.Headers) != 3 {
		t.Errorf("got %d headers, want 3", len(request.Headers))
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

func awsV4HeaderValues(headers []hm.Header) map[string]string {
	values := make(map[string]string, len(headers))
	for _, header := range headers {
		if header.Value != nil {
			values[strings.ToLower(header.Name)] = *header.Value
		}
	}
	return values
}
