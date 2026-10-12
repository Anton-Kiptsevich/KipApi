package creds

type HMACCreds struct {
	Algorithm           string
	Encoding            string
	SignatureHeaderName string
	PartsSeparator      string
	PartsSourses        []string
}