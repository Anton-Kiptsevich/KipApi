package http

type Request struct {
	CredsId string
	Method  string
	BaseUrl string
	Path    string
	Headers []Header
	Body    string
}