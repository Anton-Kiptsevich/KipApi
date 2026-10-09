package http

import "crypto/tls"

type Request struct {
	Method     string
	BaseUrl    string
	Path       string
	Headers    []Header
	Body       string
	TlsCert    *tls.Certificate
}
