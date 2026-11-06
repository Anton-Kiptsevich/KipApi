package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func TestGetAWSV4AuthorizationWithExistingDate(t *testing.T) {
	const requestDate = "20261106T090000Z"

	headers, overrideExistingHeaders, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader(awsDateHeader, requestDate)},
	}, creds.AWSV4Creds{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if !overrideExistingHeaders {
		t.Error("overrideExistingHeaders = false, want true when the request already has X-Amz-Date")
	}

	if len(headers) != 2 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 2", len(headers))
	}

	headerNames := make(map[string]bool, len(headers))
	for _, header := range headers {
		headerNames[header.Name] = true
	}
	if !headerNames["Authorization"] {
		t.Error("Authorization header is missing")
	}
	if !headerNames[awsPayloadHashHeader] {
		t.Errorf("%s header is missing", awsPayloadHashHeader)
	}
	if headerNames[awsDateHeader] {
		t.Errorf("%s must not be returned when it already exists in the request", awsDateHeader)
	}
	if awsV4TestHeaderCount(headers, "Authorization") != 1 {
		t.Error("GetAWSV4Authorization() must return exactly one Authorization header")
	}
	if awsV4TestHeaderCount(headers, awsPayloadHashHeader) != 1 {
		t.Errorf("GetAWSV4Authorization() must return exactly one %s header", awsPayloadHashHeader)
	}
	if count := awsV4TestHeaderCount(headers, awsDateHeader); count != 0 {
		t.Errorf("GetAWSV4Authorization() returned %d %s headers, want 0", count, awsDateHeader)
	}
}

func TestGetAWSV4AuthorizationWithoutDate(t *testing.T) {
	headers, overrideExistingHeaders, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
	}, creds.AWSV4Creds{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}

	if len(headers) != 3 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 3", len(headers))
	}
	if overrideExistingHeaders {
		t.Error("overrideExistingHeaders = true, want false when the request has no date header")
	}

	if got := awsV4TestHeaderValue(headers, "Authorization"); got == "" {
		t.Error("Authorization header is missing or empty")
	}
	const wantPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := awsV4TestHeaderValue(headers, awsPayloadHashHeader); got != wantPayloadHash {
		t.Errorf("%s = %q, want %q", awsPayloadHashHeader, got, wantPayloadHash)
	}
	date := awsV4TestHeaderValue(headers, awsDateHeader)
	if date == "" {
		t.Fatalf("%s header is missing or empty", awsDateHeader)
	}
	if _, err := time.Parse(utils.GetTimeFormatPattern(), date); err != nil {
		t.Errorf("%s has invalid format %q: %v", awsDateHeader, date, err)
	}
	for _, name := range []string{"Authorization", awsPayloadHashHeader, awsDateHeader} {
		if count := awsV4TestHeaderCount(headers, name); count != 1 {
			t.Errorf("%s header count = %d, want 1", name, count)
		}
	}
}


func TestGetAWSV4AuthorizationErrors(t *testing.T) {
	tests := []struct {
		name string
		req  hm.Request
		want string
	}{
		{
			name: "invalid URL",
			req:  hm.Request{BaseUrl: "https://%zz"},
			want: "parse request URL",
		},
		{
			name: "missing host",
			req:  hm.Request{BaseUrl: "/resource"},
			want: "request URL must contain a host",
		},
		{
			name: "invalid AWS date",
			req: hm.Request{
				BaseUrl: "https://api.example.com",
				Headers: []hm.Header{newAWSHeader(awsDateHeader, "invalid-date")},
			},
			want: "invalid " + awsDateHeader,
		},
		{
			name: "invalid Date header",
			req: hm.Request{
				BaseUrl: "https://api.example.com",
				Headers: []hm.Header{newAWSHeader("Date", "invalid-date")},
			},
			want: "invalid Date header",
		},
		{
			name: "payload hash mismatch",
			req: hm.Request{
				BaseUrl: "https://api.example.com",
				Headers: []hm.Header{newAWSHeader(awsPayloadHashHeader, "invalid-hash")},
			},
			want: awsPayloadHashHeader + " does not match",
		},
		{
			name: "invalid query encoding",
			req: hm.Request{
				BaseUrl: "https://api.example.com",
				Path:    "/resource?value=%zz",
			},
			want: "parse request query",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := GetAWSV4Authorization(test.req, testAWSV4Creds())
			if err == nil {
				t.Fatal("GetAWSV4Authorization() error = nil")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("GetAWSV4Authorization() error = %q, want it to contain %q", err, test.want)
			}
		})
	}
}

func TestGetAWSV4AuthorizationUsesDateHeader(t *testing.T) {
	const dateHeader = "Fri, 06 Nov 2026 09:00:00 GMT"
	const expectedDate = "20261106T090000Z"

	headers, overrideExistingHeaders, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader("Date", dateHeader)},
	}, testAWSV4Creds())
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if !overrideExistingHeaders {
		t.Error("overrideExistingHeaders = false, want true when the request already has Date")
	}

	if len(headers) != 3 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 3", len(headers))
	}
	if got := awsV4TestHeaderValue(headers, awsDateHeader); got != expectedDate {
		t.Errorf("%s = %q, want %q", awsDateHeader, got, expectedDate)
	}
}

func TestGetAWSV4AuthorizationPrefersAWSDateHeader(t *testing.T) {
	const awsDate = "20261106T090000Z"
	headers, overrideExistingHeaders, err := GetAWSV4Authorization(hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{
			newAWSHeader(awsDateHeader, awsDate),
			newAWSHeader("Date", "invalid-date"),
		},
	}, testAWSV4Creds())
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if !overrideExistingHeaders {
		t.Error("overrideExistingHeaders = false, want true when X-Amz-Date is present")
	}
	if len(headers) != 2 {
		t.Fatalf("GetAWSV4Authorization() returned %d headers, want 2", len(headers))
	}
	if awsV4TestHeaderCount(headers, "Authorization") != 1 {
		t.Error("GetAWSV4Authorization() must return exactly one Authorization header")
	}
	if awsV4TestHeaderCount(headers, awsPayloadHashHeader) != 1 {
		t.Errorf("GetAWSV4Authorization() must return exactly one %s header", awsPayloadHashHeader)
	}
	if count := awsV4TestHeaderCount(headers, awsDateHeader); count != 0 {
		t.Errorf("GetAWSV4Authorization() returned %d %s headers, want 0", count, awsDateHeader)
	}
}

func TestGetAWSV4AuthorizationAcceptsMatchingPayloadHash(t *testing.T) {
	body := "payload"
	hash := sha256.Sum256([]byte(body))
	payloadHash := hex.EncodeToString(hash[:])

	headers, overrideExistingHeaders, err := GetAWSV4Authorization(hm.Request{
		Method:  "POST",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Body:    body,
		Headers: []hm.Header{newAWSHeader(awsPayloadHashHeader, payloadHash)},
	}, testAWSV4Creds())
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if overrideExistingHeaders {
		t.Error("overrideExistingHeaders = true, want false when no date header is present")
	}
	if got := awsV4TestHeaderValue(headers, awsPayloadHashHeader); got != payloadHash {
		t.Errorf("%s = %q, want %q", awsPayloadHashHeader, got, payloadHash)
	}
}

func TestGetAWSV4AuthorizationDoesNotMutateRequest(t *testing.T) {
	date := "20261106T090000Z"
	authorization := "caller-authorization"
	request := hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{
			newAWSHeader(awsDateHeader, date),
			newAWSHeader("Authorization", authorization),
		},
	}

	_, _, err := GetAWSV4Authorization(request, testAWSV4Creds())
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}

	if len(request.Headers) != 2 {
		t.Fatalf("request headers length = %d, want 2", len(request.Headers))
	}
	if request.Headers[0].Value == nil || *request.Headers[0].Value != date {
		t.Error("existing request date was modified")
	}
	if request.Headers[1].Value == nil || *request.Headers[1].Value != authorization {
		t.Error("existing request Authorization was modified")
	}
}

func TestGetAWSV4AuthorizationSignatureChangesWithSignedRequest(t *testing.T) {
	const requestDate = "20261106T090000Z"
	request := hm.Request{
		Method:  "GET",
		BaseUrl: "https://api.example.com",
		Path:    "/resource",
		Headers: []hm.Header{newAWSHeader(awsDateHeader, requestDate)},
	}

	first, _, err := GetAWSV4Authorization(request, testAWSV4Creds())
	if err != nil {
		t.Fatalf("first GetAWSV4Authorization() error = %v", err)
	}

	request.Path = "/another-resource"
	second, _, err := GetAWSV4Authorization(request, testAWSV4Creds())
	if err != nil {
		t.Fatalf("second GetAWSV4Authorization() error = %v", err)
	}

	firstAuthorization := awsV4TestHeaderValue(first, "Authorization")
	secondAuthorization := awsV4TestHeaderValue(second, "Authorization")
	if firstAuthorization == "" || secondAuthorization == "" {
		t.Fatal("Authorization header is missing")
	}
	if firstAuthorization == secondAuthorization {
		t.Error("signature did not change when the request path changed")
	}
}

func TestGetAWSRequestTime(t *testing.T) {
	tests := []struct {
		name          string
		headers       []hm.Header
		wantTimestamp string
		wantAddHeader bool
		wantErr       bool
	}{
		{
			name:          "AWS date",
			headers:       []hm.Header{newAWSHeader(awsDateHeader, "20261106T090000Z")},
			wantTimestamp: "20261106T090000Z",
		},
		{
			name:          "RFC1123 date",
			headers:       []hm.Header{newAWSHeader("Date", "Fri, 06 Nov 2026 09:00:00 GMT")},
			wantTimestamp: "20261106T090000Z",
			wantAddHeader: true,
		},
		{
			name:          "RFC1123Z date",
			headers:       []hm.Header{newAWSHeader("Date", "Fri, 06 Nov 2026 12:00:00 +0300")},
			wantTimestamp: "20261106T090000Z",
			wantAddHeader: true,
		},
		{
			name:    "invalid AWS date",
			headers: []hm.Header{newAWSHeader(awsDateHeader, "invalid")},
			wantErr: true,
		},
		{
			name:    "invalid Date",
			headers: []hm.Header{newAWSHeader("Date", "invalid")},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, timestamp, addDateHeader, err := getAWSRequestTime(test.headers)
			if (err != nil) != test.wantErr {
				t.Fatalf("getAWSRequestTime() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != nil {
				return
			}
			if test.wantTimestamp != "" && timestamp != test.wantTimestamp {
				t.Errorf("timestamp = %q, want %q", timestamp, test.wantTimestamp)
			}
			if addDateHeader != test.wantAddHeader {
				t.Errorf("addDateHeader = %v, want %v", addDateHeader, test.wantAddHeader)
			}
		})
	}
}

func TestGetAWSRequestTimeWithoutDate(t *testing.T) {
	before := time.Now().UTC()
	requestTime, timestamp, addDateHeader, err := getAWSRequestTime(nil)
	after := time.Now().UTC()

	if err != nil {
		t.Fatalf("getAWSRequestTime() error = %v", err)
	}
	if !addDateHeader {
		t.Error("addDateHeader = false, want true")
	}
	if requestTime.Before(before) || requestTime.After(after) {
		t.Errorf("request time %v is outside [%v, %v]", requestTime, before, after)
	}
	if got := requestTime.Format(utils.GetTimeFormatPattern()); timestamp != got {
		t.Errorf("timestamp = %q, want %q", timestamp, got)
	}
}

func TestAWSCanonicalURI(t *testing.T) {
	tests := []struct {
		input   string
		service string
		want    string
	}{
		{input: "", service: "execute-api", want: "/"},
		{input: "/", service: "execute-api", want: "/"},
		{input: "/simple/path", service: "execute-api", want: "/simple/path"},
		{input: "/a%2fb", service: "execute-api", want: "/a%252fb"},
		{input: "/a b", service: "execute-api", want: "/a%2520b"},
		{input: "/café", service: "execute-api", want: "/caf%25C3%25A9"},
		{input: "/a+b", service: "execute-api", want: "/a%2Bb"},
		{input: "/a%2fb", service: "s3", want: "/a%2Fb"},
		{input: "/a b", service: "s3", want: "/a%20b"},
		{input: "/café", service: "s3", want: "/caf%C3%A9"},
	}

	for _, test := range tests {
		t.Run(test.service+test.input, func(t *testing.T) {
			parsedURL, err := url.Parse("https://api.example.com" + test.input)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}
			got, err := awsCanonicalURI(parsedURL, test.service)
			if err != nil {
				t.Fatalf("awsCanonicalURI() error = %v", err)
			}
			if got != test.want {
				t.Errorf("awsCanonicalURI() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAWSCanonicalQuery(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
		wantErr bool
	}{
		{name: "empty", query: "", want: ""},
		{name: "sorted keys", query: "z=last&a=first", want: "a=first&z=last"},
		{name: "duplicate values", query: "a=2&a=1", want: "a=1&a=2"},
		{name: "empty value", query: "empty", want: "empty="},
		{name: "URI encoding", query: "a=b+c&space=a%20b", want: "a=b%20c&space=a%20b"},
		{name: "reserved characters", query: "slash=%2F&plus=%2B", want: "plus=%2B&slash=%2F"},
		{name: "invalid encoding", query: "a=%zz", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := awsCanonicalQuery(test.query)
			if (err != nil) != test.wantErr {
				t.Fatalf("awsCanonicalQuery() error = %v, wantErr %v", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Errorf("awsCanonicalQuery() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAWSCanonicalHeaders(t *testing.T) {
	valueOne := "  application/json  "
	valueTwo := "text/plain"
	headers := []hm.Header{
		{Name: "X-Test", Value: &valueOne},
		{Name: "x-test", Values: []string{"  second\tvalue  ", "third"}},
		{Name: "Content-Type", Value: &valueTwo},
		{Name: "Authorization", Value: awsV4TestStringPointer("must-not-be-signed")},
		{Name: "Host", Value: awsV4TestStringPointer("ignored.example.com")},
		{Name: "   ", Value: awsV4TestStringPointer("ignored")},
	}

	canonical, signed := awsCanonicalHeaders(headers, " api.example.com ")
	const wantCanonical = "content-type:text/plain\nhost:api.example.com\nx-test:application/json,second value,third\n"
	const wantSigned = "content-type;host;x-test"

	if canonical != wantCanonical {
		t.Errorf("canonical headers = %q, want %q", canonical, wantCanonical)
	}
	if signed != wantSigned {
		t.Errorf("signed headers = %q, want %q", signed, wantSigned)
	}
}

func TestNormalizeAWSHeaderValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: "value", want: "value"},
		{input: "  value  ", want: "value"},
		{input: "one\ttwo\nthree", want: "one two three"},
		{input: " one   two ", want: "one two"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			if got := normalizeAWSHeaderValue(test.input); got != test.want {
				t.Errorf("normalizeAWSHeaderValue() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestAWSURIEncode(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		preserveSlash bool
		want         string
	}{
		{name: "unreserved", value: "AZaz09-_.~", want: "AZaz09-_.~"},
		{name: "slash encoded", value: "/path/to", want: "%2Fpath%2Fto"},
		{name: "slash preserved", value: "/path/to", preserveSlash: true, want: "/path/to"},
		{name: "space and plus", value: "a b+c", want: "a%20b%2Bc"},
		{name: "UTF-8", value: "é", want: "%C3%A9"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := awsURIEncode(test.value, test.preserveSlash); got != test.want {
				t.Errorf("awsURIEncode() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGetAWSV4AuthorizationMatchesAWSReferenceVector(t *testing.T) {
	// AWS Signature Version 4 test-suite get-vanilla vector.
	// The expected signature is fixed independently of the implementation under test.
	const date = "Mon, 09 Sep 2011 23:36:00 GMT"
	request := hm.Request{
		Method:  "GET",
		BaseUrl: "https://host.foo.com",
		Path:    "/",
		Headers: []hm.Header{newAWSHeader("Date", date)},
	}
	credentials := creds.AWSV4Creds{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "host",
	}

	headers, overrideExistingHeaders, err := GetAWSV4Authorization(request, credentials)
	if err != nil {
		t.Fatalf("GetAWSV4Authorization() error = %v", err)
	}
	if !overrideExistingHeaders {
		t.Error("overrideExistingHeaders = false, want true when Date is present")
	}

	const wantAuthorization = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date, Signature=8669346105352fcd40f85d6d892aed321806bbc8c65a5aa324eb6cbc4f974838"
	if got := awsV4TestHeaderValue(headers, "Authorization"); got != wantAuthorization {
		t.Errorf("Authorization = %q, want %q", got, wantAuthorization)
	}
	if got := awsV4TestHeaderValue(headers, awsPayloadHashHeader); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("%s = %q, want SHA-256 of empty payload", awsPayloadHashHeader, got)
	}
	if got := awsV4TestHeaderValue(headers, awsDateHeader); got != "20110909T233600Z" {
		t.Errorf("%s = %q, want 20110909T233600Z", awsDateHeader, got)
	}
}


func TestGetAWSV4AuthorizationCanonicalizesQueryAndHeaders(t *testing.T) {
	const requestDate = "20261106T090000Z"

	makeRequest := func(path, headerValue string) hm.Request {
		return hm.Request{
			Method:  "GET",
			BaseUrl: "https://api.example.com",
			Path:    path,
			Headers: []hm.Header{
				newAWSHeader(awsDateHeader, requestDate),
				newAWSHeader("X-Test", headerValue),
			},
		}
	}
	getAuthorization := func(request hm.Request) string {
		t.Helper()
		headers, _, err := GetAWSV4Authorization(request, testAWSV4Creds())
		if err != nil {
			t.Fatalf("GetAWSV4Authorization() error = %v", err)
		}
		authorization := awsV4TestHeaderValue(headers, "Authorization")
		if authorization == "" {
			t.Fatal("GetAWSV4Authorization() returned an empty Authorization header")
		}
		return authorization
	}

	first := getAuthorization(makeRequest("/resource?z=last&a=first", "  value\twith  spaces "))
	reordered := getAuthorization(makeRequest("/resource?a=first&z=last", "value with spaces"))
	if first != reordered {
		t.Errorf("equivalent query/header values produced different signatures:\n%s\n%s", first, reordered)
	}

	differentQuery := getAuthorization(makeRequest("/resource?a=changed&z=last", "value with spaces"))
	if first == differentQuery {
		t.Error("signature did not change when a query value changed")
	}

	differentHeader := getAuthorization(makeRequest("/resource?a=first&z=last", "different value"))
	if first == differentHeader {
		t.Error("signature did not change when a signed header value changed")
	}
}

func testAWSV4Creds() creds.AWSV4Creds {
	return creds.AWSV4Creds{
		AccessKeyID:     "test-access-key",
		SecretAccessKey: "test-secret-key",
		Region:          "us-east-1",
		Service:         "execute-api",
	}
}

func awsV4TestHeaderCount(headers []hm.Header, name string) int {
	count := 0
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			count++
		}
	}
	return count
}

func awsV4TestHeaderValue(headers []hm.Header, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) && header.Value != nil {
			return *header.Value
		}
	}
	return ""
}

func awsV4TestStringPointer(value string) *string {
	return &value
}
