package constants

// HMAC signature placeholders.
const (
	HP_Method        = "{method}"
	HP_Url           = "{url}"
	HP_BaseUrl       = "{baseUrl}"
	HP_Scheme        = "{scheme}"
	HP_Host          = "{host}"
	HP_Port          = "{port}"
	HP_Path          = "{path}"
	HP_Query         = "{query}"
	HP_Body          = "{body}"
	HP_ContentLength = "{contentLength}"

	// Header placeholders use the form "{header:Name}".
	HP_HeaderPrefix = "{header:"
	HP_PlaceholderEnd = "}"
)
