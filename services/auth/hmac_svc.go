package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"net/url"
	"regexp"
	"strings"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/internal/utils"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func GetHMACSignature(req hm.Request, hmacCreds creds.HMACCreds) (string, error) {
	canonical, err := buildCanonicalSignature(req, hmacCreds)
	if err != nil {
		return "", err
	}

	var hashFunc func() hash.Hash
	switch hmacCreds.Algorithm {
	case constants.HA_SHA1:
		hashFunc = sha1.New
	case constants.HA_SHA256:
		hashFunc = sha256.New
	case constants.HA_SHA384:
		hashFunc = sha512.New384
	case constants.HA_SHA512:
		hashFunc = sha512.New
	default:
		panic("unsupported HMAC algorithm")
	}

	signature := hmac.New(hashFunc, []byte(hmacCreds.SecretKey))
	_, _ = signature.Write([]byte(canonical))
	sum := signature.Sum(nil)

	switch hmacCreds.SignatureEncoding {
	case "base64":
		return base64.StdEncoding.EncodeToString(sum), nil
	case "hex":
		return hex.EncodeToString(sum), nil
	default:
		panic("unsupported HMAC signature encoding")
	}
}

func buildCanonicalSignature(req hm.Request, hmacCreds creds.HMACCreds) (string, error) {
	fullURL := req.BaseUrl + req.Path
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		panic("Incorrect request url")
	}

	values := map[string]string{
		constants.SP_Method:        req.Method,
		constants.SP_Url:           fullURL,
		constants.SP_BaseUrl:       req.BaseUrl,
		constants.SP_Scheme:        parsedURL.Scheme,
		constants.SP_Host:          parsedURL.Hostname(),
		constants.SP_Port:          parsedURL.Port(),
		constants.SP_Path:          parsedURL.EscapedPath(),
		constants.SP_Query:         parsedURL.RawQuery,
		constants.SP_Body:          req.Body,
		constants.SP_ContentLength: fmt.Sprint(len([]byte(req.Body))),
	}

	canonical := regexp.MustCompile(constants.SP_REGEXP_PATTERN).ReplaceAllStringFunc(hmacCreds.Signature, func(placeholder string) string {
		if err != nil {
			return ""
		}
		value, exists := values[placeholder]
		if !exists {
			if strings.HasPrefix(placeholder, "{header:") {
				value = requestHeaderValue(req.Headers, utils.GetHeaderNameFromPlaceholder(placeholder))
			} else {
				return placeholder
			}
		}

		if canonicalize := hmacCreds.PlaceholderCanonicalizationFuncs[placeholder]; canonicalize != nil {
			value, err = canonicalize(value)
			if err != nil {
				err = fmt.Errorf("canonicalize placeholder %s: %w", placeholder, err)
				return ""
			}
		}
		return value
	})
	if err != nil {
		return "", err
	}
	return canonical, nil
}

func requestHeaderValue(headers []hm.Header, name string) string {
	for _, header := range headers {
		if !strings.EqualFold(header.Name, name) {
			continue
		}
		if header.Value != nil {
			return *header.Value
		}
		if header.Values != nil {
			return strings.Join(header.Values, ", ")
		}
		return ""
	}
	return ""
}
