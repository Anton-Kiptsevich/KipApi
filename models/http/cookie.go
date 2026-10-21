package http

import "time"

type Cookie struct {
	Name    string
	Value   string
	Expires time.Time
	MaxAge  int
	Path    string
	Domain  string
}
