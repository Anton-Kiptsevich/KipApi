package utils

import (
	"fmt"

	"github.com/Anton-Kiptsevich/KipApi/models"
)

func ValidateHttpRequest(req *models.HttpRequest) error {
	for _, h := range req.Headers {
		if (h.Value == "") == (h.Values == nil) {
			return fmt.Errorf("Header can only have either Value or Values")
		}
	}

	return nil
}