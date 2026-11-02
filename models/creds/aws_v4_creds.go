package creds

type AWSV4Creds struct {
	AccessKeyID     string
	SecretAccessKey string

	Region  string
	Service string

	Signature []string // Each element is a template processed sequentially by the HMAC chain.
	PlaceholderCanonicalizationFuncs map[string]func(value string) (string, error)
}
