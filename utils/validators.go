package utils

import (
	"crypto/tls"
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

func ValidateCreds(id string, c creds.Creds) error {
	switch c.CredsType {
	case constants.CT_Basic:
		basic, ok := c.Creds.(creds.BasicCreds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires BasicCreds", id, c.CredsType) 
		}
		if basic.Username == "" || basic.Password == "" { 
			return fmt.Errorf("%s: BasicCreds must contain Username and Password", id) 
		}
	case constants.CT_Bearer:
		bearer, ok := c.Creds.(creds.BearerCreds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires BearerCreds", id, c.CredsType) 
		}
		if bearer.Token == "" { 
			return fmt.Errorf("%s: BearerCreds must contain Token", id) 
		}
	case constants.CT_OAuth2:
		oauth2, ok := c.Creds.(creds.OAuth2Creds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires OAuth2Creds", id, c.CredsType) 
		}
		if oauth2.AccessToken == "" || oauth2.RefreshToken == "" || oauth2.TokenURL == "" || oauth2.ClientID == "" || oauth2.ClientSecret == "" || oauth2.ExpirationDate.IsZero() {
			return fmt.Errorf("%s: OAuth2Creds must contain AccessToken, RefreshToken, ExpirationDate, TokenURL, ClientID and ClientSecret", id)
		}
	case constants.CT_ApiKey:
		apiKey, ok := c.Creds.(creds.ApiKeyCreds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires ApiKeyCreds", id, c.CredsType) 
		}
		if apiKey.ApiKey == "" || apiKey.FieldName == "" { 
			return fmt.Errorf("%s: ApiKeyCreds must contain ApiKey and FieldName", id) 
		}
	case constants.CT_Digest:
		digest, ok := c.Creds.(creds.DigestCreds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires DigestCreds", id, c.CredsType) 
		}
		if digest.Username == "" || digest.Password == "" { 
			return fmt.Errorf("%s: DigestCreds must contain Username and Password", id) 
		}
	case constants.CT_MTLS:
		mtls, ok := c.Creds.(creds.MTLSCreds)
		if !ok { 
			return fmt.Errorf("%s: CredsType %s requires MTLSCreds", id, c.CredsType) 
		}
		if len(mtls.ClientCert) == 0 || len(mtls.ClientKey) == 0 { 
			return fmt.Errorf("%s: MTLSCreds must contain ClientCert and ClientKey", id) 
		}
		if _, err := tls.X509KeyPair(mtls.ClientCert, mtls.ClientKey); err != nil {
			return fmt.Errorf("%s: MTLSCreds contains invalid ClientCert/ClientKey pair: %w", id, err)
		}
	default:
		return fmt.Errorf("%s: Unknown CredsType %s", id, c.CredsType)
	}
	return nil
}

func ValidateAuthMethod(authMethod, credsType string) error {
	switch authMethod {
	case constants.AM_Basic:
		if credsType != constants.CT_Basic { 
			return fmt.Errorf("AuthMethod %s requires %s credentials", authMethod, constants.CT_Basic) 
		}
	case constants.AM_Bearer:
		if credsType != constants.CT_Bearer && credsType != constants.CT_OAuth2 { 
			return fmt.Errorf("AuthMethod %s requires Bearer or OAuth2 credentials", authMethod) 
		}
	case constants.AM_Header, constants.AM_Query:
		if credsType != constants.CT_ApiKey { 
			return fmt.Errorf("AuthMethod %s requires %s credentials", authMethod, constants.CT_ApiKey) 
		}
	case constants.AM_Digest:
		if credsType != constants.CT_Digest { 
			return fmt.Errorf("AuthMethod %s requires %s credentials", authMethod, constants.CT_Digest) 
		}
	case constants.AM_MTLS:
		if credsType != constants.CT_MTLS { 
			return fmt.Errorf("AuthMethod %s requires %s credentials", authMethod, constants.CT_MTLS) 
		}
	default:
		return fmt.Errorf("Unknown AuthMethod %s", authMethod)
	}
	return nil
}
