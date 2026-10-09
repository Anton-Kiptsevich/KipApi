package services

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestMakeApiCallAuthorizationAgainstLocalServer(t *testing.T) {
	tests := []struct {
		name string
		authMethod string
		credential creds.Creds
		check func(*testing.T, *http.Request)
	}{
		{
			name: "basic", authMethod: constants.AM_Basic,
			credential: creds.Creds{Id: "basic-integration", CredsType: constants.CT_Basic, Creds: creds.BasicCreds{Username: "user", Password: "pass"}},
			check: func(t *testing.T, r *http.Request) {
				want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
				if got := r.Header.Get("Authorization"); got != want { t.Errorf("Authorization = %q, want %q", got, want) }
			},
		},
		{
			name: "bearer", authMethod: constants.AM_Bearer,
			credential: creds.Creds{Id: "bearer-integration", CredsType: constants.CT_Bearer, Creds: creds.BearerCreds{Token: "test-token"}},
			check: func(t *testing.T, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" { t.Errorf("Authorization = %q, want Bearer test-token", got) }
			},
		},
		{
			name: "API key header", authMethod: constants.AM_Header,
			credential: creds.Creds{Id: "header-integration", CredsType: constants.CT_ApiKey, Creds: creds.ApiKeyCreds{ApiKey: "api-secret", FieldName: "X-API-Key"}},
			check: func(t *testing.T, r *http.Request) {
				if got := r.Header.Get("X-API-Key"); got != "api-secret" { t.Errorf("X-API-Key = %q, want api-secret", got) }
			},
		},
		{
			name: "API key query", authMethod: constants.AM_Query,
			credential: creds.Creds{Id: "query-integration", CredsType: constants.CT_ApiKey, Creds: creds.ApiKeyCreds{ApiKey: "api-secret", FieldName: "api_key"}},
			check: func(t *testing.T, r *http.Request) {
				if got := r.URL.Query().Get("api_key"); got != "api-secret" { t.Errorf("api_key query = %q, want api-secret", got) }
				if got := r.URL.Query().Get("existing"); got != "preserved" { t.Errorf("existing query = %q, want preserved", got) }
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitCredsSvc()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.check(t, r)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			if errs := SetCreds([]creds.Creds{tt.credential}, false); len(errs) != 0 { t.Fatalf("SetCreds() errors = %v", errs) }
			path := "/resource"
			if tt.authMethod == constants.AM_Query { path += "?existing=preserved" }
			response, err := MakeApiCall(hm.ApiCall{
				CredsId: tt.credential.Id, AuthMethod: tt.authMethod,
				Request: hm.Request{Method: http.MethodGet, BaseUrl: server.URL, Path: path},
			})
			if err != nil { t.Fatalf("MakeApiCall() error = %v", err) }
			if response.Status != "204 No Content" { t.Fatalf("response status = %q, want 204 No Content", response.Status) }
		})
	}
}

func TestMakeApiCallPreservesCallerAuthorizationHeader(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{Id: "preserve-auth", CredsType: constants.CT_Bearer, Creds: creds.BearerCreds{Token: "stored-token"}}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) != 0 { t.Fatalf("SetCreds() errors = %v", errs) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Custom supplied-value" { t.Errorf("Authorization = %q, want caller-provided value", got) }
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	customValue := "Custom supplied-value"
	response, err := MakeApiCall(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Bearer,
		Request: hm.Request{Method: http.MethodGet, BaseUrl: server.URL, Path: "/resource", Headers: []hm.Header{{Name: "Authorization", Value: &customValue}}},
	})
	if err != nil { t.Fatalf("MakeApiCall() error = %v", err) }
	if response.Status != "204 No Content" { t.Fatalf("response status = %q, want 204 No Content", response.Status) }
}

func TestMakeApiCallDigestChallenge(t *testing.T) {
	InitCredsSvc()
	credential := creds.Creds{Id: "digest-integration", CredsType: constants.CT_Digest, Creds: creds.DigestCreds{Username: "user", Password: "pass"}}
	if errs := SetCreds([]creds.Creds{credential}, false); len(errs) != 0 { t.Fatalf("SetCreds() errors = %v", errs) }
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		authorization := r.Header.Get("Authorization")
		if !strings.HasPrefix(authorization, "Digest ") {
			w.Header().Set("WWW-Authenticate", `Digest realm="test-realm", nonce="test-nonce", qop="auth"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !strings.Contains(authorization, `username="user"`) || !strings.Contains(authorization, `realm="test-realm"`) {
			t.Errorf("unexpected Digest Authorization header: %q", authorization)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	response, err := MakeApiCall(hm.ApiCall{
		CredsId: credential.Id, AuthMethod: constants.AM_Digest,
		Request: hm.Request{Method: http.MethodGet, BaseUrl: server.URL, Path: "/resource"},
	})
	if err != nil { t.Fatalf("MakeApiCall() error = %v", err) }
	if requestCount != 2 { t.Fatalf("request count = %d, want initial challenge and authenticated request", requestCount) }
	if response.Status != "204 No Content" { t.Fatalf("response status = %q, want 204 No Content", response.Status) }
}
