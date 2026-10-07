package http

type Response struct {
	Status  string
	Headers []Header
	Body    string
}
