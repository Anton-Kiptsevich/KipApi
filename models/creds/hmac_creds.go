package creds

type HMACCreds struct {
	Algorithm              string
	SecretKey              string
	SignatureEncoding      string
	SignatureHeaderName    string
	CanonicalizedSignature string // tokens to replace with actual data should be in { }
}