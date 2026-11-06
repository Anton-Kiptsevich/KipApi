package auth

import (
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetAWSV4AuthorizationWithExistingDate(t *testing.T) {
	const requestDate = "20261106T090000Z"

	headers, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader(awsDateHeader, requestDate)},
	}, creds.AWSV4Creds{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}

	if len(headers) != 2 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 2", len(headers))
	}

	headerNames := make(map[string]bool, len(headers))
	for _, header := range headers {
		headerNames[header.Name] = true
	}
	if !headerNames["Authorization"] {
		t.Error("Authorization header is missing")
	}
	if !headerNames[awsPayloadHashHeader] {
		t.Errorf("%s header is missing", awsPayloadHashHeader)
	}
	if headerNames[awsDateHeader] {
		t.Errorf("%s must not be returned when it already exists in the request", awsDateHeader)
	}
}

func TestGetAWSV4AuthorizationWithoutDate(t *testing.T) {
	headers, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
	}, creds.AWSV4Creds{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}

	if len(headers) != 3 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 3", len(headers))
	}

	headerValues := make(map[string]string, len(headers))
	for _, header := range headers {
		if header.Value != nil {
			headerValues[header.Name] = *header.Value
		}
	}
	if _, exists := headerValues["Authorization"]; !exists {
		t.Error("Authorization header is missing")
	}
	if _, exists := headerValues[awsPayloadHashHeader]; !exists {
		t.Errorf("%s header is missing", awsPayloadHashHeader)
	}
	date, exists := headerValues[awsDateHeader]
	if !exists {
		t.Fatalf("%s header is missing", awsDateHeader)
	}
	if _, err := time.Parse(utils.GetTimeFormatPattern(), date); err != nil {
		t.Errorf("%s has invalid format %q: %v", awsDateHeader, date, err)
	}
}
