package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetAWSV4Authorization(t *testing.T) {
	const timestamp = "20240102T030405Z"
	body := `{"message":"hello"}`
	headerValue := "  value\twith  spaces "
	req := hm.Request{
		Method:  "POST",
		BaseUrl: "https://example.com",
		Path:    "/resource?z=last&a=first",
		Headers: []hm.Header{
			newAWSHeader(awsDateHeader, timestamp),
			newAWSHeader("X-Test", headerValue),
		},
		Body: body,
	}
	awsCreds := creds.AWSV4Creds{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	}

	headers, err := GetAWSV4Authorization(req, awsCreds)
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if len(headers) != 2 {
		t.Fatalf("got %d headers, want Authorization and payload hash", len(headers))
	}

	values := make(map[string]string, len(headers))
	for _, header := range headers {
		if header.Value == nil {
			t.Fatalf("%s has nil Value", header.Name)
		}
		values[strings.ToLower(header.Name)] = *header.Value
	}

	authorization := values["authorization"]
	for _, expected := range []string{
		"AWS4-HMAC-SHA256 ",
		"Credential=access-key/20240102/us-east-1/execute-api/aws4_request",
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-test",
		"Signature=",
	} {
		if !strings.Contains(authorization, expected) {
			t.Errorf("Authorization %q does not contain %q", authorization, expected)
		}
	}
	signature := strings.Split(authorization, "Signature=")[1]
	if len(signature) != sha256.Size*2 {
		t.Errorf("signature length = %d, want %d", len(signature), sha256.Size*2)
	}
	if _, err := hex.DecodeString(signature); err != nil {
		t.Errorf("signature is not hexadecimal: %v", err)
	}

	payloadHash := sha256.Sum256([]byte(body))
	if got, want := values[strings.ToLower(awsPayloadHashHeader)], hex.EncodeToString(payloadHash[:]); got != want {
		t.Errorf("%s = %q, want %q", awsPayloadHashHeader, got, want)
	}
}

func TestGetAWSV4AuthorizationAddsDateHeader(t *testing.T) {
	headers, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/resource",
	}, creds.AWSV4Creds{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if len(headers) != 3 {
		t.Fatalf("got %d headers, want Authorization, payload hash and date", len(headers))
	}

	var date string
	for _, header := range headers {
		if strings.EqualFold(header.Name, awsDateHeader) && header.Value != nil {
			date = *header.Value
		}
	}
	if date == "" {
		t.Fatal("generated AWS date header is missing")
	}
	if _, err := time.Parse("20060102T150405Z", date); err != nil {
		t.Errorf("generated AWS date %q is invalid: %v", date, err)
	}
}

func TestGetAWSV4AuthorizationRejectsMismatchedPayloadHash(t *testing.T) {
	wrongHash := strings.Repeat("0", sha256.Size*2)
	_, err := GetAWSV4Authorization(hm.Request{
		Method:  "POST",
		BaseUrl: "https://example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader(awsPayloadHashHeader, wrongHash)},
		Body:    "payload",
	}, creds.AWSV4Creds{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err == nil {
		t.Fatal("GetAWSV4Authorization() error = nil, want payload hash mismatch")
	}
}

func TestGetAWSV4AuthorizationRejectsInvalidDate(t *testing.T) {
	_, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader(awsDateHeader, "invalid-date")},
	}, creds.AWSV4Creds{
		AccessKeyID:     "access-key",
		SecretAccessKey: "secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err == nil {
		t.Fatal("GetAWSV4Authorization() error = nil, want invalid date error")
	}
}

func TestAWSCanonicalURI(t *testing.T) {
	parsedURL, err := url.Parse("https://example.com/a%20b/c%2fd")
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	got, err := awsCanonicalURI(parsedURL)
	if err != nil {
		t.Fatalf("awsCanonicalURI() error = %v", err)
	}
	if want := "/a%20b/c%2Fd"; got != want {
		t.Errorf("awsCanonicalURI() = %q, want %q", got, want)
	}
}

func TestAWSCanonicalQuery(t *testing.T) {
	got, err := awsCanonicalQuery("z=last&a=hello+world&tag=two&tag=one")
	if err != nil {
		t.Fatalf("awsCanonicalQuery() error = %v", err)
	}
	if want := "a=hello%20world&tag=one&tag=two&z=last"; got != want {
		t.Errorf("awsCanonicalQuery() = %q, want %q", got, want)
	}

	if _, err := awsCanonicalQuery("a=%zz"); err == nil {
		t.Error("awsCanonicalQuery() error = nil, want malformed query error")
	}
}

func TestAWSCanonicalHeaders(t *testing.T) {
	value := "  value\twith  spaces "
	headers := []hm.Header{
		{Name: "X-Test", Value: &value},
		{Name: "Authorization", Value: &value},
	}
	canonical, signed := awsCanonicalHeaders(headers, "example.com")
	if want := "host:example.com\nx-test:value with spaces\n"; canonical != want {
		t.Errorf("canonical headers = %q, want %q", canonical, want)
	}
	if want := "host;x-test"; signed != want {
		t.Errorf("signed headers = %q, want %q", signed, want)
	}
}
