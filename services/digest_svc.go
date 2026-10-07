package services

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func getDigestAuthorization(req hm.Request, currentCreds creds.Creds) (string, error) {
	digestCreds, ok := currentCreds.Creds.(creds.DigestCreds)
	if !ok {
		return "", fmt.Errorf("credentials with id %s are not Digest credentials", currentCreds.Id)
	}

	challengeReq := req
	challengeReq.Headers = removeHeader(challengeReq.Headers, "Authorization")

	res, err := MakeHttpRequest(&challengeReq)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(res.Status, "401 ") {
		return "", fmt.Errorf("Digest authentication challenge failed with status %s", res.Status)
	}

	challenge, err := getDigestChallenge(res.Headers)
	if err != nil {
		return "", err
	}
	if challenge.Algorithm != "" && !strings.EqualFold(challenge.Algorithm, "MD5") {
		return "", fmt.Errorf("unsupported Digest algorithm %s", challenge.Algorithm)
	}
	if challenge.Qop != "" && !containsToken(challenge.Qop, "auth") {
		return "", fmt.Errorf("unsupported Digest qop %s", challenge.Qop)
	}

	uri := req.Path
	if uri == "" { uri = "/" }
	if parsed, err := url.Parse(req.BaseUrl + req.Path); err == nil { uri = parsed.RequestURI() }

	ha1 := md5Hex(digestCreds.Username + ":" + challenge.Realm + ":" + digestCreds.Password)
	ha2 := md5Hex(req.Method + ":" + uri)

	if challenge.Qop == "" {
		response := md5Hex(ha1 + ":" + challenge.Nonce + ":" + ha2)
		return "Digest username=\"" + digestCreds.Username + "\", realm=\"" + challenge.Realm + "\", nonce=\"" + challenge.Nonce + "\", uri=\"" + uri + "\", response=\"" + response + "\"", nil
	}

	cnonce, err := generateCnonce()
	if err != nil { return "", err }
	nc := "00000001"
	response := md5Hex(ha1 + ":" + challenge.Nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	authorization := "Digest username=\"" + digestCreds.Username + "\", realm=\"" + challenge.Realm + "\", nonce=\"" + challenge.Nonce + "\", uri=\"" + uri + "\", algorithm=MD5, qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\", response=\"" + response + "\""
	if challenge.Opaque != "" { authorization += ", opaque=\"" + challenge.Opaque + "\"" }
	return authorization, nil
}

type digestChallenge struct {
	Realm string
	Nonce string
	Algorithm string
	Qop string
	Opaque string
}

func getDigestChallenge(headers []hm.Header) (digestChallenge, error) {
	for _, header := range headers {
		if !strings.EqualFold(header.Name, "WWW-Authenticate") || header.Value == nil { continue }
		value := strings.TrimSpace(*header.Value)
		if !strings.HasPrefix(strings.ToLower(value), "digest ") { continue }
		params, err := parseDigestParams(strings.TrimSpace(value[len("Digest "):]))
		if err != nil { return digestChallenge{}, err }
		challenge := digestChallenge{Realm: params["realm"], Nonce: params["nonce"], Algorithm: params["algorithm"], Qop: params["qop"], Opaque: params["opaque"]}
		if challenge.Realm == "" || challenge.Nonce == "" { return digestChallenge{}, fmt.Errorf("Digest challenge must contain realm and nonce") }
		return challenge, nil
	}
	return digestChallenge{}, fmt.Errorf("Digest challenge was not found in WWW-Authenticate")
}

func parseDigestParams(value string) (map[string]string, error) {
	result := make(map[string]string)
	for {
		value = strings.TrimSpace(value)
		if value == "" { return result, nil }
		eq := strings.IndexByte(value, '=')
		if eq <= 0 { return nil, fmt.Errorf("invalid Digest parameter %q", value) }
		name := strings.TrimSpace(value[:eq])
		value = strings.TrimSpace(value[eq+1:])
		var parameter string
		if strings.HasPrefix(value, "\"") {
			end := 1
			for end < len(value) {
				if value[end] == '"' && value[end-1] != '\\' { break }
				end++
			}
			if end >= len(value) { return nil, fmt.Errorf("unterminated Digest parameter %s", name) }
			parameter = value[1:end]
			value = value[end+1:]
		} else {
			comma := strings.IndexByte(value, ',')
			if comma == -1 { parameter = strings.TrimSpace(value); value = "" } else { parameter = strings.TrimSpace(value[:comma]); value = value[comma+1:] }
		}
		result[strings.ToLower(name)] = parameter
	}
}

func md5Hex(value string) string {
	hash := md5.Sum([]byte(value))
	return hex.EncodeToString(hash[:])
}

func generateCnonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { return "", err }
	return hex.EncodeToString(b), nil
}

func containsToken(value, token string) bool {
	for _, item := range strings.Split(value, ",") { if strings.EqualFold(strings.TrimSpace(item), token) { return true } }
	return false
}