package base

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestMakeHttpRequestAgainstLocalServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("request method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/items" || r.URL.Query().Get("source") != "test" {
			t.Errorf("request URL = %q, want /items?source=test", r.URL.String())
		}
		if r.Header.Get("X-Test") != "header-value" {
			t.Errorf("X-Test = %q, want header-value", r.Header.Get("X-Test"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("reading request body: %v", err)
		}
		if string(body) != "payload" {
			t.Errorf("request body = %q, want payload", body)
		}
		w.Header().Add("X-Result", "first")
		w.Header().Add("X-Result", "second")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer server.Close()

	headerValue := "header-value"
	response, err := MakeHttpRequest(&hm.Request{
		Method: http.MethodPost, BaseUrl: server.URL, Path: "/items?source=test",
		Headers: []hm.Header{{Name: "X-Test", Value: &headerValue}}, Body: "payload",
	})
	if err != nil {
		t.Fatalf("MakeHttpRequest() error = %v", err)
	}
	if response.Status != "201 Created" {
		t.Fatalf("response status = %q, want 201 Created", response.Status)
	}
	if response.Body != "created" {
		t.Fatalf("response body = %q, want created", response.Body)
	}
	var values []string
	for _, h := range response.Headers {
		if strings.EqualFold(h.Name, "X-Result") && h.Value != nil {
			values = append(values, *h.Value)
		}
	}
	if len(values) != 2 || values[0] != "first" || values[1] != "second" {
		t.Fatalf("X-Result response headers = %#v, want [first second]", values)
	}
}

func TestMakeHttpRequestReturnsHTTPErrorStatusAsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	response, err := MakeHttpRequest(&hm.Request{Method: http.MethodGet, BaseUrl: server.URL, Path: "/private"})
	if err != nil {
		t.Fatalf("MakeHttpRequest() error = %v; HTTP status codes should be returned as responses", err)
	}
	if response.Status != "403 Forbidden" {
		t.Fatalf("response status = %q, want 403 Forbidden", response.Status)
	}
	if !strings.Contains(response.Body, "forbidden") {
		t.Fatalf("response body = %q, want forbidden", response.Body)
	}
}

func TestMakeHttpRequestRejectsMalformedURL(t *testing.T) {
	_, err := MakeHttpRequest(&hm.Request{Method: http.MethodGet, BaseUrl: "http://example.com", Path: "/bad%zz"})
	if err == nil {
		t.Fatal("MakeHttpRequest() error = nil, want malformed URL error")
	}
}
