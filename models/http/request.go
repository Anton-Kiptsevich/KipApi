package http

import "crypto/tls"

type Request struct {
	CredsId    string
	AuthMethod string
	Method     string
	BaseUrl    string
	Path       string
	Headers    []Header
	Body       string
	TlsCert    *tls.Certificate
}
