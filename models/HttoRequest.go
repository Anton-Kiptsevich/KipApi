package models

import "github.com/Anton-Kiptsevich/KipApi/models"

type HttpRequest struct {
	Method  string
	BaseUrl string
	Path    string
	Headers map[models.HttpHeader]
	Body    string
}