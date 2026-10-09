package http

type AuthorizedRequest struct {
	CredsId     string
	AuthMethod  string
	HttoRequest Request
}