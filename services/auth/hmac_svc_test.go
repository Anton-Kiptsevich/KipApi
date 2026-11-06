package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetHMACSignatureAppliesPlaceholderCanonicalization(t *testing.T) {
	requestID := "request id"
	req := hm.Request{
		Method:  "POST",
		BaseUrl: "https://example.com",
		Path:    "/resource?x=1",
		Body:    "hello",
		Headers: []hm.Header{{Name: "X-Request-Id", Value: &requestID}},
	}
	canonicalizationCalled := false
	credentials := creds.HMACCreds{
		Algorithm:                       constants.HA_SHA256,
		SecretKey:                       "secret",
		SignatureEncoding:               "hex",
		SignatureHeaderName:             "X-Signature",
		Signature:                       "{method}|{url}|{body}|{header:X-Request-Id}",
		PlaceholderCanonicalizationFuncs: map[string]func(string) (string, error){
			"{header:X-Request-Id}": func(value string) (string, error) {
				canonicalizationCalled = true
				return strings.ReplaceAll(value, " ", "%20"), nil
			},
		},
	}

	got, err := GetHMACSignature(req, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() error = %v", err)
	}
	if !canonicalizationCalled {
		t.Fatal("placeholder canonicalization function was not called")
	}
	const want = "79e66e5a688372c9d0d82686739d1df9a81468d568170c90c2a191a9fe190d58"
	if got != want {
		t.Fatalf("GetHMACSignature() = %q, want %q", got, want)
	}
	if *req.Headers[0].Value != requestID {
		t.Fatal("GetHMACSignature() modified the original request header")
	}
}

func TestGetHMACSignatureMissingHeaderUsesEmptyValue(t *testing.T) {
	got, err := GetHMACSignature(hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/",
	}, creds.HMACCreds{
		Algorithm:         constants.HA_SHA256,
		SecretKey:         "secret",
		SignatureEncoding: "hex",
		Signature:         "{method}|{header:X-Missing}",
	})
	if err != nil {
		t.Fatalf("GetHMACSignature() error = %v", err)
	}
	if got == "" {
		t.Fatal("GetHMACSignature() returned an empty signature")
	}
}


func TestGetHMACSignatureSupportsBase64Encoding(t *testing.T) {
	request := hm.Request{
		Method:  "POST",
		BaseUrl: "https://example.com",
		Path:    "/resource",
		Body:    "payload",
	}
	credentials := creds.HMACCreds{
		Algorithm:         constants.HA_SHA256,
		SecretKey:         "secret",
		SignatureEncoding: "hex",
		Signature:         "{method}|{url}|{body}",
	}

	hexSignature, err := GetHMACSignature(request, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() with hex encoding error = %v", err)
	}
	signatureBytes, err := hex.DecodeString(hexSignature)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}

	credentials.SignatureEncoding = "base64"
	base64Signature, err := GetHMACSignature(request, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() with base64 encoding error = %v", err)
	}
	if want := base64.StdEncoding.EncodeToString(signatureBytes); base64Signature != want {
		t.Fatalf("GetHMACSignature() with base64 encoding = %q, want %q", base64Signature, want)
	}
}

func TestGetHMACSignatureReturnsCanonicalizationError(t *testing.T) {
	wantErr := errors.New("canonicalization failed")
	credentials := creds.HMACCreds{
		Algorithm:         constants.HA_SHA256,
		SecretKey:         "secret",
		SignatureEncoding: "hex",
		Signature:         "{method}|{body}",
		PlaceholderCanonicalizationFuncs: map[string]func(string) (string, error){
			"{body}": func(string) (string, error) {
				return "", wantErr
			},
		},
	}

	got, err := GetHMACSignature(hm.Request{
		Method:  "POST",
		BaseUrl: "https://example.com",
		Path:    "/",
		Body:    "payload",
	}, credentials)
	if err == nil {
		t.Fatal("GetHMACSignature() error = nil, want canonicalization error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("GetHMACSignature() error = %v, want wrapped error %v", err, wantErr)
	}
	if got != "" {
		t.Fatalf("GetHMACSignature() = %q, want empty signature on error", got)
	}
}

func TestGetHMACSignatureUsesEmptyValueForExistingEmptyHeader(t *testing.T) {
	emptyValue := ""
	request := hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/",
		Headers: []hm.Header{{Name: "X-Empty", Value: &emptyValue}},
	}
	credentials := creds.HMACCreds{
		Algorithm:         constants.HA_SHA256,
		SecretKey:         "secret",
		SignatureEncoding: "hex",
		Signature:         "{method}|{header:X-Empty}",
	}

	withEmptyHeader, err := GetHMACSignature(request, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() error = %v", err)
	}
	withoutHeader, err := GetHMACSignature(hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/",
	}, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() without header error = %v", err)
	}
	if withEmptyHeader != withoutHeader {
		t.Fatalf("signature with empty header = %q, without header = %q; want equal signatures", withEmptyHeader, withoutHeader)
	}
}

func TestGetHMACSignatureSupportsRepeatedPlaceholders(t *testing.T) {
	request := hm.Request{
		Method:  "GET",
		BaseUrl: "https://example.com",
		Path:    "/resource",
	}
	credentials := creds.HMACCreds{
		Algorithm:         constants.HA_SHA256,
		SecretKey:         "secret",
		SignatureEncoding: "hex",
		Signature:         "{method}|{method}|{path}|{path}",
	}

	got, err := GetHMACSignature(request, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() error = %v", err)
	}
	credentials.Signature = "GET|GET|/resource|/resource"
	want, err := GetHMACSignature(request, credentials)
	if err != nil {
		t.Fatalf("GetHMACSignature() for literal signature error = %v", err)
	}
	if got != want {
		t.Fatalf("GetHMACSignature() = %q, want %q", got, want)
	}
}
