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
		basic, ok := c.Creds.(creds.BasicCreds)
		if !ok {
			return fmt.Errorf("CredsType %s requires BasicCreds", c.CredsType)
		}
		if basic.Username == "" || basic.Password == "" {
			return fmt.Errorf("BasicCreds must contain Username and Password")
		}
	case constants.CT_Bearer:
		bearer, ok := c.Creds.(creds.BearerCreds)
		if !ok {
			return fmt.Errorf("CredsType %s requires BearerCreds", c.CredsType)
		}
		if bearer.Token == "" {
			return fmt.Errorf("BearerCreds must contain Token")
		}
	case constants.CT_OAuth2:
		oauth2, ok := c.Creds.(creds.OAuth2Creds)
		if !ok {
			return fmt.Errorf("CredsType %s requires OAuth2Creds", c.CredsType)
		}
		if oauth2.AccessToken == "" || oauth2.RefreshToken == "" {
			return fmt.Errorf("OAuth2Creds must contain AccessToken and RefreshToken")
		}
	default:
		return fmt.Errorf("Unknown CredsType %s", c.CredsType)
	}

	return nil
}
