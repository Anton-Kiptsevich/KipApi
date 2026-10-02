package models

type HttpRequest struct {
	Method  string
	BaseUrl string
	Path    string
	Headers []HttpHeader
	Body    string
}