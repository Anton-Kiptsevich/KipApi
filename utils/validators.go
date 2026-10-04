package utils

import (
	"fmt"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func ValidateHttpRequest(req *hm.Request) error {
	headers := make(map[string]struct{})
	for _, h := range req.Headers {
		_, ok := headers[h.Name]
		if ok {
			return fmt.Errorf("Duplicate header %s", h.Name)
		}
		headers[h.Name] = struct{}{}
		if (h.Value == nil) == (h.Values == nil) {
			return fmt.Errorf("Header can only have either Value or Values")
		}
	}

	return nil
}