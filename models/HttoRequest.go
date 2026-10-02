package models

import "github.com/Anton-Kiptsevich/KipApi/models"

type HttpRequest struct {
	Method  string
	BaseUrl string
	Path    string
	Headers []models.HttpHeader
	Body    string
}