package base

import (
	"net/http"
	"testing"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestMakeHttpRequestRejectsMalformedURL(t *testing.T) {
	_, err := MakeHttpRequest(&hm.Request{
		Method:  http.MethodGet,
		BaseUrl: "http://example.com",
		Path:    "/bad%zz",
	})
	if err == nil {
		t.Fatal("MakeHttpRequest() error = nil, want malformed URL error")
	}
}
