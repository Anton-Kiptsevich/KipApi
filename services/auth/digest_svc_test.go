package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetDigestAuthorizationReferenceCalculations(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		qop       string
		body      string
	}{
		{name: "MD5 without qop", algorithm: "MD5"},
		{name: "SHA-256 without qop", algorithm: "SHA-256"},
		{name: "MD5 qop auth", algorithm: "MD5", qop: "auth"},
		{name: "MD5 qop auth-int", algorithm: "MD5", qop: "auth-int", body: "request body"},
		{name: "MD5-sess qop auth", algorithm: "MD5-sess", qop: "auth"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const realm = "test-realm"
			const nonce = "fixed-server-nonce"
			challenge := fmt.Sprintf("Digest realm=%q, nonce=%q", realm, nonce)
			if test.algorithm != "" {
				challenge += fmt.Sprintf(", algorithm=%s", test.algorithm)
			}
			if test.qop != "" {
				challenge += fmt.Sprintf(", qop=%q", test.qop)
			}
			challenge += `, opaque="fixed-opaque"`

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", challenge)
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()

			request := hm.Request{
				Method:  http.MethodPost,
				BaseUrl: server.URL,
				Path:    "/resource?item=1",
				Body:    test.body,
			}
			currentCreds := creds.Creds{
				Id:        "digest-test",
				CredsType: constants.CT_Digest,
				Creds:     creds.DigestCreds{Username: "test-user", Password: "test-password"},
			}

			authorization, err := GetDigestAuthorization(request, currentCreds)
			if err != nil {
				t.Fatalf("GetDigestAuthorization() error = %v", err)
			}
			if !strings.HasPrefix(authorization, "Digest ") {
				t.Fatalf("authorization = %q, want Digest scheme", authorization)
			}
			params, err := parseDigestParams(strings.TrimPrefix(authorization, "Digest "))
			if err != nil {
				t.Fatalf("parseDigestParams() error = %v", err)
			}

			if params["username"] != "test-user" || params["realm"] != realm || params["nonce"] != nonce {
				t.Fatalf("unexpected identity/challenge parameters: %#v", params)
			}
			if params["uri"] != "/resource?item=1" {
				t.Errorf("uri = %q, want /resource?item=1", params["uri"])
			}
			if params["opaque"] != "fixed-opaque" {
				t.Errorf("opaque = %q, want fixed-opaque", params["opaque"])
			}

			algorithm := strings.ToLower(test.algorithm)
			if algorithm == "" {
				algorithm = "md5"
			}
			qop := test.qop
			cnonce := params["cnonce"]
			if qop != "" {
				if params["qop"] != qop || params["nc"] != "00000001" || cnonce == "" {
					t.Fatalf("unexpected qop parameters: %#v", params)
				}
			} else if params["qop"] != "" || cnonce != "" || params["nc"] != "" {
				t.Fatalf("unexpected qop parameters for challenge without qop: %#v", params)
			}

			ha1 := digestTestHash(algorithm, "test-user:"+realm+":test-password")
			if algorithm == "md5-sess" {
				ha1 = digestTestHash(algorithm, ha1+":"+nonce+":"+cnonce)
			}
			ha2Input := request.Method + ":" + params["uri"]
			if qop == "auth-int" {
				ha2Input += ":" + digestTestHash(algorithm, test.body)
			}
			ha2 := digestTestHash(algorithm, ha2Input)

			var expected string
			if qop == "" {
				expected = digestTestHash(algorithm, ha1+":"+nonce+":"+ha2)
			} else {
				expected = digestTestHash(algorithm, ha1+":"+nonce+":00000001:"+cnonce+":"+qop+":"+ha2)
			}
			if params["response"] != expected {
				t.Errorf("response = %q, want independently calculated %q", params["response"], expected)
			}
		}
	}
}

func TestGetDigestAuthorizationRejectsUnsupportedQop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Digest realm="test", nonce="nonce", qop="auth-conf"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	_, err := GetDigestAuthorization(hm.Request{
		Method: http.MethodGet, BaseUrl: server.URL, Path: "/",
	}, creds.Creds{
		Id: "digest-test", CredsType: constants.CT_Digest,
		Creds: creds.DigestCreds{Username: "user", Password: "password"},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported Digest qop") {
		t.Fatalf("GetDigestAuthorization() error = %v, want unsupported qop error", err)
	}
}

func digestTestHash(algorithm, value string) string {
	var sum []byte
	switch algorithm {
	case "md5", "md5-sess":
		hash := md5.Sum([]byte(value))
		sum = hash[:]
	case "sha-256":
		hash := sha256.Sum256([]byte(value))
		sum = hash[:]
	default:
		panic("unsupported digest test algorithm")
	}
	return hex.EncodeToString(sum)
}
