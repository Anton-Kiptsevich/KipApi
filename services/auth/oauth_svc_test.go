package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
)

func TestRefreshOAuthTokenPreservesRefreshTokenWhenNotRotated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want form encoding", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old-refresh" ||
			r.Form.Get("client_id") != "client-id" || r.Form.Get("client_secret") != "client-secret" {
			t.Errorf("unexpected token request form: %#v", url.Values(r.Form))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "new-access", "expires_in": 3600})
	}))
	defer server.Close()

	current := creds.Creds{
		Id: "oauth-1", CredsType: constants.CT_OAuth2,
		Creds: creds.OAuth2Creds{AccessToken: "old-access", RefreshToken: "old-refresh", ExpirationDate: time.Now().Add(-time.Minute), TokenURL: server.URL, ClientID: "client-id", ClientSecret: "client-secret"},
	}
	updated, err := RefreshOAuthToken(current)
	if err != nil {
		t.Fatalf("RefreshOAuthToken() error = %v", err)
	}
	got := updated.Creds.(creds.OAuth2Creds)
	if got.AccessToken != "new-access" {
		t.Fatalf("AccessToken = %q, want new-access", got.AccessToken)
	}
	if got.RefreshToken != "old-refresh" {
		t.Fatalf("RefreshToken = %q, want old-refresh when omitted by server", got.RefreshToken)
	}
	if time.Until(got.ExpirationDate) < 50*time.Minute {
		t.Fatalf("ExpirationDate is not approximately one hour in the future: %v", got.ExpirationDate)
	}
	if updated.Id != current.Id || updated.CredsType != current.CredsType {
		t.Fatalf("credential identity/type changed: %#v", updated)
	}
}

func TestRefreshOAuthTokenAcceptsRotatedRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"rotated-refresh","expires_in":600}`))
	}))
	defer server.Close()
	current := creds.Creds{
		Id: "oauth-2", CredsType: constants.CT_OAuth2,
		Creds: creds.OAuth2Creds{AccessToken: "old-access", RefreshToken: "old-refresh", ExpirationDate: time.Now(), TokenURL: server.URL, ClientID: "client-id", ClientSecret: "client-secret"},
	}
	updated, err := RefreshOAuthToken(current)
	if err != nil {
		t.Fatalf("RefreshOAuthToken() error = %v", err)
	}
	if got := updated.Creds.(creds.OAuth2Creds).RefreshToken; got != "rotated-refresh" {
		t.Fatalf("RefreshToken = %q, want rotated-refresh", got)
	}
}

func TestRefreshOAuthTokenRejectsInvalidResponses(t *testing.T) {
	tests := []struct {
		name string
		statusCode int
		body string
	}{
		{"non-success status", http.StatusBadRequest, `{"error":"invalid_grant"}`},
		{"invalid JSON", http.StatusOK, "not-json"},
		{"missing access token", http.StatusOK, `{"expires_in":3600}`},
		{"invalid expiration", http.StatusOK, `{"access_token":"token","expires_in":0}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			current := creds.Creds{
				Id: "oauth-error", CredsType: constants.CT_OAuth2,
				Creds: creds.OAuth2Creds{AccessToken: "old", RefreshToken: "refresh", ExpirationDate: time.Now(), TokenURL: server.URL, ClientID: "client", ClientSecret: "secret"},
			}
			if _, err := RefreshOAuthToken(current); err == nil {
				t.Fatal("RefreshOAuthToken() error = nil, want error")
			}
		})
	}
}
