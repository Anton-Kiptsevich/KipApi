package http

type Request struct {
	CredsId    string
	AuthMethod string
	Method     string
	BaseUrl    string
	Path       string
	Headers    []Header
	Body       string
}
