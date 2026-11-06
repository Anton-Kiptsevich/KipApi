package auth

import (
	"strings"
	"testing"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestParseTokenResponse(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		body      string
		want      tokenResponse
		wantError string
	}{
		{
			name: "complete token response",
			status: "200 OK",
			body: `{"access_token":"access","refresh_token":"refresh","expires_in":3600}`,
			want: tokenResponse{AccessToken: "access", RefreshToken: "refresh", ExpiresIn: 3600},
		},
		{
			name: "refresh token may be omitted",
			status: "200 OK",
			body: `{"access_token":"access","expires_in":600}`,
			want: tokenResponse{AccessToken: "access", ExpiresIn: 600},
		},
		{name: "empty response status", body: `{"access_token":"access","expires_in":600}`, wantError: "empty response status"},
		{name: "non-success status", status: "400 Bad Request", body: `{"error":"invalid_grant"}`, wantError: "failed with status 400 Bad Request"},
		{name: "malformed status", status: "invalid-status", body: `{"access_token":"access","expires_in":600}`, wantError: "failed to parse"},
		{name: "invalid JSON", status: "200 OK", body: "not-json", wantError: "failed to parse"},
		{name: "missing access token", status: "200 OK", body: `{"expires_in":3600}`, wantError: "does not contain access_token"},
		{name: "zero expiration", status: "200 OK", body: `{"access_token":"access","expires_in":0}`, wantError: "does not contain valid expires_in"},
		{name: "negative expiration", status: "200 OK", body: `{"access_token":"access","expires_in":-1}`, wantError: "does not contain valid expires_in"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseTokenResponse(hm.Response{Status: test.status, Body: test.body}, "OAuth2 token refresh")
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("parseTokenResponse() error = %v, want error containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTokenResponse() error = %v", err)
			}
			if got != test.want {
				t.Errorf("parseTokenResponse() = %#v, want %#v", got, test.want)
			}
		})
	}
}
