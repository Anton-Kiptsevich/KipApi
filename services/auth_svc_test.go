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
	if len(request.Headers) != 3 {
		t.Fatalf("got %d headers, want 3", len(request.Headers))
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
	if _, err := time.Parse(utils.GetTimeFormatPattern(), *request.Headers[2].Value); err != nil {
		t.Errorf("generated X-Amz-Date has invalid format: %v", err)
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
