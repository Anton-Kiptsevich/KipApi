package utils

import (
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetHeaderNameFromPlaceholder(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"header name", "{header:Authorization}", "Authorization"},
		{"empty header name", "{header:}", ""},
		{"not a header placeholder", "{method}", ""},
		{"other wildcard placeholder", "{future:anything}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetHeaderNameFromPlaceholder(tt.input); got != tt.want {
				t.Fatalf("GetHeaderNameFromPlaceholder(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReplaceHeaderNameWithWildcard(t *testing.T) {
	tests := []struct {
		name, input, want string
	}{
		{"header placeholder", "{header:Authorization}", constants.SP_Header},
		{"empty header name", "{header:}", constants.SP_Header},
		{"fixed placeholder", constants.SP_Method, constants.SP_Method},
		{"unknown wildcard placeholder", "{future:anything}", "{future:anything}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReplaceHeaderNameWithWildcard(tt.input); got != tt.want {
				t.Fatalf("ReplaceHeaderNameWithWildcard(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateHMACSignatureRequest(t *testing.T) {
	value := "present"
	tests := []struct {
		name, signature string
		headers []hm.Header
		wantErr bool
	}{
		{"header present", "{header:Authorization}", []hm.Header{{Name: "authorization", Value: &value}}, false},
		{"header missing", "{header:Authorization}", nil, true},
		{"empty header name", "{header:}", nil, true},
		{"no header placeholder", "{method}", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHMACSignatureRequest(tt.signature, hm.Request{Headers: tt.headers})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateHMACSignatureRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHttpRequestHeaders(t *testing.T) {
	value := "application/json"
	tests := []struct {
		name string
		headers []hm.Header
		wantErr bool
	}{
		{name: "single value", headers: []hm.Header{{Name: "Accept", Value: &value}}},
		{name: "multiple values", headers: []hm.Header{{Name: "Accept", Values: []string{"application/json", "text/plain"}}}},
		{name: "missing value", headers: []hm.Header{{Name: "Accept"}}, wantErr: true},
		{name: "both value forms", headers: []hm.Header{{Name: "Accept", Value: &value, Values: []string{"text/plain"}}}, wantErr: true},
		{name: "duplicate name", headers: []hm.Header{{Name: "Accept", Value: &value}, {Name: "Accept", Values: []string{"text/plain"}}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHttpRequest(&hm.Request{Method: "GET", BaseUrl: "https://example.com", Path: "/resource", Headers: tt.headers})
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateHttpRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHttpRequestRejectsMalformedURL(t *testing.T) {
	err := ValidateHttpRequest(&hm.Request{Method: "GET", BaseUrl: "https://example.com", Path: "/bad%zz"})
	if err == nil {
		t.Fatal("ValidateHttpRequest() error = nil, want malformed URL error")
	}
}

func TestValidateCreds(t *testing.T) {
	valid := []struct {
		name string
		c creds.Creds
	}{
		{"basic", creds.Creds{CredsType: constants.CT_Basic, Creds: creds.BasicCreds{Username: "user", Password: "pass"}}},
		{"bearer", creds.Creds{CredsType: constants.CT_Bearer, Creds: creds.BearerCreds{Token: "token"}}},
		{"api key", creds.Creds{CredsType: constants.CT_ApiKey, Creds: creds.ApiKeyCreds{ApiKey: "key", FieldName: "X-API-Key"}}},
		{"oauth2", creds.Creds{CredsType: constants.CT_OAuth2, Creds: creds.OAuth2Creds{AccessToken: "access", RefreshToken: "refresh", ExpirationDate: time.Now().Add(time.Hour), TokenURL: "https://example.com/token", ClientID: "client", ClientSecret: "secret"}}},
		{"hmac with header placeholder", creds.Creds{CredsType: constants.CT_HMAC, Creds: creds.HMACCreds{Algorithm: constants.HA_SHA256, SecretKey: "secret", SignatureEncoding: "hex", SignatureHeaderName: "X-Signature", Signature: "{method}:{header:X-Request-Id}"}}},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCreds("test-id", tt.c); err != nil {
				t.Fatalf("ValidateCreds() error = %v", err)
			}
		})
	}
	invalid := []struct {
		name string
		c creds.Creds
	}{
		{"wrong model", creds.Creds{CredsType: constants.CT_Basic, Creds: creds.BearerCreds{Token: "token"}}},
		{"empty bearer token", creds.Creds{CredsType: constants.CT_Bearer, Creds: creds.BearerCreds{}}},
		{"empty api key field name", creds.Creds{CredsType: constants.CT_ApiKey, Creds: creds.ApiKeyCreds{ApiKey: "key"}}},
		{"unknown type", creds.Creds{CredsType: "unknown", Creds: struct{}{}}},
		{"unknown hmac placeholder", creds.Creds{CredsType: constants.CT_HMAC, Creds: creds.HMACCreds{Algorithm: constants.HA_SHA256, SecretKey: "secret", SignatureEncoding: "hex", SignatureHeaderName: "X-Signature", Signature: "{future:anything}"}}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateCreds("test-id", tt.c); err == nil {
				t.Fatal("ValidateCreds() error = nil, want validation error")
			}
		})
	}
}

func TestValidateAuthMethod(t *testing.T) {
	valid := []struct{ method, credsType string }{
		{constants.AM_Basic, constants.CT_Basic}, {constants.AM_Bearer, constants.CT_Bearer},
		{constants.AM_Bearer, constants.CT_OAuth2}, {constants.AM_Header, constants.CT_ApiKey},
		{constants.AM_Query, constants.CT_ApiKey}, {constants.AM_Digest, constants.CT_Digest},
		{constants.AM_MTLS, constants.CT_MTLS}, {constants.AM_HMAC, constants.CT_HMAC},
	}
	for _, tt := range valid {
		t.Run(tt.method+"/"+tt.credsType, func(t *testing.T) {
			if err := ValidateAuthMethod(tt.method, tt.credsType); err != nil {
				t.Fatalf("ValidateAuthMethod() error = %v", err)
			}
		})
	}
	invalid := []struct{ method, credsType string }{
		{constants.AM_Basic, constants.CT_Bearer}, {constants.AM_Bearer, constants.CT_ApiKey},
		{constants.AM_Header, constants.CT_Bearer}, {constants.AM_Query, constants.CT_OAuth2},
		{"unknown", constants.CT_Basic},
	}
	for _, tt := range invalid {
		t.Run(tt.method+"/"+tt.credsType, func(t *testing.T) {
			if err := ValidateAuthMethod(tt.method, tt.credsType); err == nil {
				t.Fatalf("ValidateAuthMethod() error = nil, want validation error")
			}
		})
	}
}
