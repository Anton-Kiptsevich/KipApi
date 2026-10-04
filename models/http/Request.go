package http

type Request struct {
	Method  string
	BaseUrl string
	Path    string
	Headers []Header
	Body    string
}