package auth

import (
	"strings"
	"testing"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetDigestChallenge(t *testing.T) {
	tests := []struct {
		name    string
		headers []hm.Header
		want    digestChallenge
		wantErr string
	}{
		{
			name: "all supported parameters",
			headers: []hm.Header{
				{Name: "WWW-Authenticate", Value: digestTestHeaderValue(`Digest realm="test-realm", nonce="test-nonce", algorithm=SHA-256, qop="auth,auth-int", opaque="test-opaque"`)},
			},
			want: digestChallenge{
				Realm: "test-realm", Nonce: "test-nonce", Algorithm: "SHA-256",
				Qop: "auth,auth-int", Opaque: "test-opaque",
			},
		},
		{
			name: "case-insensitive header and scheme",
			headers: []hm.Header{
				{Name: "www-authenticate", Value: digestTestHeaderValue(`digest realm="realm", nonce="nonce"`)},
			},
			want: digestChallenge{Realm: "realm", Nonce: "nonce"},
		},
		{
			name: "challenge header is absent",
			headers: []hm.Header{
				{Name: "Content-Type", Value: digestTestHeaderValue("application/json")},
			},
			wantErr: "Digest challenge was not found",
		},
		{
			name: "realm is missing",
			headers: []hm.Header{
				{Name: "WWW-Authenticate", Value: digestTestHeaderValue(`Digest nonce="nonce"`)},
			},
			wantErr: "must contain realm and nonce",
		},
		{
			name: "nonce is missing",
			headers: []hm.Header{
				{Name: "WWW-Authenticate", Value: digestTestHeaderValue(`Digest realm="realm"`)},
			},
			wantErr: "must contain realm and nonce",
		},
		{
			name: "malformed parameter",
			headers: []hm.Header{
				{Name: "WWW-Authenticate", Value: digestTestHeaderValue(`Digest realm="realm", broken`)},
			},
			wantErr: "invalid Digest parameter",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getDigestChallenge(test.headers)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("getDigestChallenge() error = %v, want error containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("getDigestChallenge() error = %v", err)
			}
			if got != test.want {
				t.Errorf("getDigestChallenge() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseDigestParams(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    map[string]string
		wantErr string
	}{
		{
			name:  "quoted and unquoted values",
			input: `username="test-user", algorithm=SHA-256, qop="auth,auth-int", nonce="test-nonce"`,
			want: map[string]string{
				"username": "test-user",
				"algorithm": "SHA-256",
				"qop": "auth,auth-int",
				"nonce": "test-nonce",
			},
		},
		{
			name:  "parameter names are normalized",
			input: `Realm="test-realm", NONCE="test-nonce"`,
			want: map[string]string{"realm": "test-realm", "nonce": "test-nonce"},
		},
		{
			name:    "missing equals sign",
			input:   `realm="test", broken`,
			wantErr: "invalid Digest parameter",
		},
		{
			name:    "unterminated quoted value",
			input:   `realm="test`,
			wantErr: "unterminated Digest parameter",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDigestParams(test.input)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("parseDigestParams() error = %v, want error containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDigestParams() error = %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("parseDigestParams() = %#v, want %#v", got, test.want)
			}
			for key, want := range test.want {
				if got[key] != want {
					t.Errorf("parameter %q = %q, want %q", key, got[key], want)
				}
			}
		})
	}
}

func TestContainsToken(t *testing.T) {
	tests := []struct {
		value string
		token string
		want  bool
	}{
		{value: "auth,auth-int", token: "auth", want: true},
		{value: "AUTH-INT, AUTH", token: "auth", want: true},
		{value: "auth-int", token: "auth", want: false},
		{value: "auth", token: "auth-int", want: false},
	}

	for _, test := range tests {
		if got := containsToken(test.value, test.token); got != test.want {
			t.Errorf("containsToken(%q, %q) = %v, want %v", test.value, test.token, got, test.want)
		}
	}
}

func digestTestHeaderValue(value string) *string {
	return &value
}
