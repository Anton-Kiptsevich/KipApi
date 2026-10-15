package auth

import (
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
