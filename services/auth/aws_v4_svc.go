package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

const (
	aws4Algorithm = "AWS4-HMAC-SHA256"
	aws4Terminator = "aws4_request"
	awsDateHeader = "X-Amz-Date"
	awsPayloadHashHeader = "X-Amz-Content-Sha256"
)

func GetAWSV4Authorization(req *hm.Request, awsCreds creds.AWSV4Creds) (string, error) {
	if req == nil {
		return "", fmt.Errorf("request must not be nil")
	}

	parsedURL, err := url.Parse(req.BaseUrl + req.Path)
	if err != nil {
		return "", fmt.Errorf("parse request URL: %w", err)
	}
	if parsedURL.Host == "" {
		return "", fmt.Errorf("request URL must contain a host")
	}

	requestTime, timestamp, err := getAWSRequestTime(req)
	if err != nil {
		return "", err
	}
	date := requestTime.Format("20060102")

	payloadHash := sha256.Sum256([]byte(req.Body))
	payloadHashHex := hex.EncodeToString(payloadHash[:])
	if existing := requestHeaderValue(req.Headers, awsPayloadHashHeader); existing != "" && existing != payloadHashHex {
		return "", fmt.Errorf("%s does not match the request body SHA-256", awsPayloadHashHeader)
	}
	if strings.EqualFold(awsCreds.Service, "s3") || requestHeaderValue(req.Headers, awsPayloadHashHeader) != "" {
		setRequestHeader(req, awsPayloadHashHeader, payloadHashHex)
	}

	host := parsedURL.Host
	if parsedURL.Port() != "" && !strings.Contains(host, "]") {
		host = net.JoinHostPort(parsedURL.Hostname(), parsedURL.Port())
	}

	canonicalURI, err := awsCanonicalURI(parsedURL)
	if err != nil {
		return "", err
	}
	canonicalQuery, err := awsCanonicalQuery(parsedURL.RawQuery)
	if err != nil {
		return "", err
	}
	canonicalHeaders, signedHeaders := awsCanonicalHeaders(req.Headers, host)

	canonicalRequest := strings.Join([]string{
		strings.ToUpper(req.Method),
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHashHex,
	}, "\n")

	canonicalRequestHash := sha256.Sum256([]byte(canonicalRequest))
	scope := date + "/" + awsCreds.Region + "/" + awsCreds.Service + "/" + aws4Terminator
	stringToSign := strings.Join([]string{
		aws4Algorithm,
		timestamp,
		scope,
		hex.EncodeToString(canonicalRequestHash[:]),
	}, "\n")

	signingKey := utils.CalculateHMACChain(
		[]byte("AWS4"+awsCreds.SecretAccessKey),
		[]string{date, awsCreds.Region, awsCreds.Service, aws4Terminator},
		"SHA256",
	)
	signature := hex.EncodeToString(utils.CalculateHMACChain(signingKey, []string{stringToSign}, "SHA256"))

	return fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		aws4Algorithm, awsCreds.AccessKeyID, scope, signedHeaders, signature), nil
}

func getAWSRequestTime(req *hm.Request) (time.Time, string, error) {
	if value := requestHeaderValue(req.Headers, awsDateHeader); value != "" {
		t, err := time.Parse("20060102T150405Z", value)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("invalid %s: %w", awsDateHeader, err)
		}
		return t, value, nil
	}
	if value := requestHeaderValue(req.Headers, "Date"); value != "" {
		t, err := time.Parse(time.RFC1123, value)
		if err != nil {
			t, err = time.Parse(time.RFC1123Z, value)
		}
		if err != nil {
			return time.Time{}, "", fmt.Errorf("invalid Date header: %w", err)
		}
		t = t.UTC()
		return t, t.Format("20060102T150405Z"), nil
	}

	t := time.Now().UTC()
	value := t.Format("20060102T150405Z")
	setRequestHeader(req, awsDateHeader, value)
	return t, value, nil
}

func awsCanonicalURI(u *url.URL) (string, error) {
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	const hexDigits = "0123456789ABCDEF"
	var result strings.Builder
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '%' && i+2 < len(path) && isHex(path[i+1]) && isHex(path[i+2]) {
			result.WriteByte('%')
			result.WriteByte(byte(strings.ToUpper(string(path[i+1]))[0]))
			result.WriteByte(byte(strings.ToUpper(string(path[i+2]))[0]))
			i += 2
			continue
		}
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("-_.~/", rune(c)) {
			result.WriteByte(c)
		} else {
			result.WriteByte('%')
			result.WriteByte(hexDigits[c>>4])
			result.WriteByte(hexDigits[c&15])
		}
	}
	return result.String(), nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func awsCanonicalQuery(rawQuery string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("parse request query: %w", err)
	}
	var pairs []string
	for key, entries := range values {
		if len(entries) == 0 {
			entries = []string{""}
		}
		for _, value := range entries {
			pairs = append(pairs, awsURIEncode(key, false)+"="+awsURIEncode(value, false))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&"), nil
}

func awsCanonicalHeaders(headers []hm.Header, host string) (string, string) {
	values := map[string][]string{"host": {strings.TrimSpace(host)}}
	for _, header := range headers {
		name := strings.ToLower(strings.TrimSpace(header.Name))
		if name == "" || name == "authorization" || name == "host" {
			continue
		}
		var headerValues []string
		if header.Value != nil {
			headerValues = append(headerValues, *header.Value)
		} else {
			headerValues = append(headerValues, header.Values...)
		}
		for _, value := range headerValues {
			values[name] = append(values[name], normalizeAWSHeaderValue(value))
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(values[name], ","))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(names, ";")
}

func normalizeAWSHeaderValue(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func awsURIEncode(value string, preserveSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var result strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("-_.~", rune(c)) ||
			(preserveSlash && c == '/') {
			result.WriteByte(c)
		} else {
			result.WriteByte('%')
			result.WriteByte(hexDigits[c>>4])
			result.WriteByte(hexDigits[c&15])
		}
	}
	return result.String()
}

func setRequestHeader(req *hm.Request, name, value string) {
	for i := range req.Headers {
		if strings.EqualFold(req.Headers[i].Name, name) {
			valueCopy := value
			req.Headers[i].Value = &valueCopy
			req.Headers[i].Values = nil
			return
		}
	}
	valueCopy := value
	req.Headers = append(req.Headers, hm.Header{Name: name, Value: &valueCopy})
}
