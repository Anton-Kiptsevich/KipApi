package creds

type HMACCreds struct {
	Algorithm                        string
	SecretKey                        string
	SignatureEncoding                string
	SignatureHeaderName              string
	Signature                        string // tokens to replace with actual data should be in { }
	PlaceholderCanonicalizationFuncs map[string]func(value string) (string, error)
}