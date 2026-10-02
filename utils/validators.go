package utils

import (
	"fmt"

	"github.com/Anton-Kiptsevich/KipApi/models"
)

func ValidateHttpRequest(req *models.HttpRequest) error {
	headers := make(map[string]struct{})
	for _, h := range req.Headers {
		_, ok := headers[h.name]
		if ok {
			return fmt.Errorf("Duplicate header")
		}
		headers[h.name] = struct{}{}
		if (h.Value == "") == (h.Values == nil) {
			return fmt.Errorf("Header can only have either Value or Values")
		}
	}

	return nil
}