package auth

import (
	"strings"

	hm "github.com/Anton-Kiptsevich/KipApi/models/http"
)

func requestHeaderValue(headers []hm.Header, name string) string {
	for _, header := range headers {
		if !strings.EqualFold(header.Name, name) {
			continue
		}
		if header.Value != nil {
			return *header.Value
		}
		if header.Values != nil {
			return strings.Join(header.Values, ", ")
		}
		return ""
	}
	return ""
}
