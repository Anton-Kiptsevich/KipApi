package utils

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/Anton-Kiptsevich/KipApi/constants"
)

func CalculateHMACChain(key []byte, data []string, algorithm string) []byte {
	var hashFunc func() hash.Hash

	switch algorithm {
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

	result := key
	for _, value := range data {
		signature := hmac.New(hashFunc, result)
		_, _ = signature.Write([]byte(value))
		result = signature.Sum(nil)
	}

	return result
}
