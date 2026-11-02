package creds

type AWSV4Creds struct {
	AccessKeyID     string
	SecretAccessKey string

	Region  string
	Service string
}
