package services

import (
	"crypto/md5"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetDigestAuthorization(t *testing.T) {
	const (
		username = "Mufasa"
		password = "Circle Of Life"
		realm    = "testrealm@host.com"
		nonce    = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		if authorization == "" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s", qop="auth"`, realm, nonce))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(authorization, "Digest ") {
			t.Errorf("unexpected authorization scheme: %s", authorization)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		params, err := parseDigestParams(strings.TrimPrefix(authorization, "Digest "))
		if err != nil {
			t.Errorf("failed to parse authorization: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ha1 := md5Hex(username + ":" + realm + ":" + password)
		ha2 := md5Hex(r.Method + ":" + params["uri"])
		expected := md5Hex(ha1 + ":" + nonce + ":" + params["nc"] + ":" + params["cnonce"] + ":auth:" + ha2)
		if params["response"] != expected {
			t.Errorf("unexpected response: got %s, want %s", params["response"], expected)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))

	defer server.Close()

	req := hm.Request{
		Method:  http.MethodGet,
		BaseUrl: server.URL,
		Path:    "/resource",
	}
	currentCreds := creds.Creds{
		Id:        "digest-test",
		CredsType: constants.CT_Digest,
		Creds: creds.DigestCreds{
			Username: username,
			Password: password,
		},
	}

	authorization, err := getDigestAuthorization(req, currentCreds)
	if err != nil {
		t.Fatalf("getDigestAuthorization returned error: %v", err)
	}

	if !strings.HasPrefix(authorization, "Digest ") {
		t.Fatalf("unexpected authorization value: %s", authorization)
	}
}
