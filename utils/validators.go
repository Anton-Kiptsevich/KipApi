package utils

import (
	"fmt"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
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

func ValidateCreds(c creds.Creds) error {
	switch c.CredsType {
	case constants.CT_Basic:
		if _, ok := c.Creds.(creds.BasicCreds); !ok {
			return fmt.Errorf("CredsType %s requires BasicCreds", c.CredsType)
		}
	case constants.CT_Bearer:
		if _, ok := c.Creds.(creds.BearerCreds); !ok {
			return fmt.Errorf("CredsType %s requires BearerCreds", c.CredsType)
		}
	case constants.CT_OAuth2:
		if _, ok := c.Creds.(creds.OAuth2Creds); !ok {
			return fmt.Errorf("CredsType %s requires OAuth2Creds", c.CredsType)
		}
	default:
		return fmt.Errorf("Unknown CredsType %s", c.CredsType)
	}

	return nil
}
