# KipApi

KipApi is a Go library for making HTTP requests to external APIs with reusable credential and authentication handling. It provides integration infrastructure—not API-specific clients, business logic, or persistent storage.

## Installation

```bash
go get github.com/Anton-Kiptsevich/KipApi
```

## Quick start

The usual flow is:

1. Initialize KipApi's in-memory credential store once during application startup.
2. Register credentials with `SetCreds`.
3. Call `MakeApiCall` with a credential ID, authentication method, and HTTP request.
4. Handle the response and any returned error.

This example sends a GET request with a Bearer token:

```go
package main

import (
	"fmt"
	"log"

	"github.com/Anton-Kiptsevich/KipApi/constants"
	"github.com/Anton-Kiptsevich/KipApi/models/creds"
	httpmodel "github.com/Anton-Kiptsevich/KipApi/models/http"
	"github.com/Anton-Kiptsevich/KipApi/services"
)

func main() {
	// Initialize once during application startup.
	services.InitCredsSvc()

	credential := creds.Creds{
		Id:        "credential-123",
		CredsType: constants.CT_Bearer,
		Creds:     creds.BearerCreds{Token: "YOUR_ACCESS_TOKEN"},
	}
	if errs := services.SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
		for _, err := range errs {
			log.Println("invalid credentials:", err)
		}
		return
	}

	call := httpmodel.ApiCall{
		CredsId:    "credential-123",
		AuthMethod: constants.AM_Bearer,
		Request: httpmodel.Request{
			Method:  "GET",
			BaseUrl: "https://api.example.com",
			Path:    "/users",
		},
	}

	response, err := services.MakeApiCall(call)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(response.Status)
	fmt.Println(response.Body)
}
```

Replace the example URL and token with your API's values. Load real secrets from configuration or a secret store; do not hard-code them in source control.

## Credentials and authentication

A credential describes the secret material you have. An authentication method describes how that material is sent with a request. These are configured separately.

| Credential type | Model | Authentication method |
|---|---|---|
| Basic username/password | `creds.BasicCreds` | `constants.AM_Basic` |
| Static Bearer token | `creds.BearerCreds` | `constants.AM_Bearer` |
| OAuth 2.0 tokens | `creds.OAuth2Creds` | `constants.AM_Bearer` |
| API key | `creds.ApiKeyCreds` | `constants.AM_Header` or `constants.AM_Query` |
| Digest username/password | `creds.DigestCreds` | `constants.AM_Digest` |
| Client certificate/key | `creds.MTLSCreds` | `constants.AM_MTLS` |
| Cookie authentication | `creds.CookieCreds` | `constants.AM_Cookie` |
| HMAC signature | `creds.HMACCreds` | `constants.AM_HMAC` |

Wrap a specific credential model in `creds.Creds`:

```go
credential := creds.Creds{
    Id:        "credential-456",
    CredsType: constants.CT_Basic,
    Creds: creds.BasicCreds{
        Username: "YOUR_USERNAME",
        Password: "YOUR_PASSWORD",
    },
}
errs := services.SetCreds([]creds.Creds{credential}, false)
```

`Id` is the identifier of this credential record in your application. It can be any non-empty string; it does not have to be a GUID/UUID. It must be unique within the scope of KipApi's in-memory store and remain stable when the same record is updated or loaded again. For example, you can use your database primary key or a namespaced key if IDs are only unique within a tenant or service. KipApi uses this ID for `MakeApiCall`, and returns it as the key in `GetCredsForSync`; pass the same ID to `MarkCredsSynced` after saving the record. `SetCreds` validates each credential and returns validation errors, or `nil` if all entries are valid.

For an API key, `creds.ApiKeyCreds.FieldName` is the header name for `AM_Header`, or the query parameter name for `AM_Query`. KipApi adds the key only if that header or query parameter is not already present.

## Making an authenticated request

`httpmodel.ApiCall` combines the credential ID, authentication method, and HTTP request:

```go
call := httpmodel.ApiCall{
    CredsId:    "credential-456",
    AuthMethod: constants.AM_Header,
    Request: httpmodel.Request{
        Method:  "GET",
        BaseUrl: "https://api.example.com",
        Path:    "/users",
    },
}
response, err := services.MakeApiCall(call)
```

`httpmodel.Request` fields:

- `Method`: HTTP method, such as `GET`, `POST`, `PUT`, or `DELETE`.
- `BaseUrl`: base URL, such as `https://api.example.com`.
- `Path`: endpoint path, such as `/users`.
- `Headers`: optional request headers.
- `Cookies`: optional request cookies.
- `Body`: optional request body as a string.
- `TlsCert`: optional TLS client certificate.

If the request already has an `Authorization` header, KipApi leaves it unchanged. For `AM_Header`, an existing header with the configured `FieldName` is also left unchanged.

### Headers and body

Each `httpmodel.Header` must set exactly one of `Value` or `Values`. Use `Value` for one value and `Values` for multiple values. Header names must not be empty or duplicated; duplicate detection is case-insensitive.

```go
contentType := "application/json"
request := httpmodel.Request{
    Method:  "POST",
    BaseUrl: "https://api.example.com",
    Path:    "/users",
    Headers: []httpmodel.Header{
        {Name: "Content-Type", Value: &contentType},
    },
    Body: `{"name":"Example"}`,
}
```

KipApi sends `Body` as supplied; it does not serialize application structs into JSON. Encode your payload before assigning it.

## Cookie authentication

Use Cookie authentication when an API expects session or other authentication cookies. Register the cookies in `creds.CookieCreds` and use `constants.AM_Cookie` for the request.

```go
credential := creds.Creds{
    Id:        "cookie-credential",
    CredsType: constants.CT_Cookie,
    Creds: creds.CookieCreds{
        Cookies: []httpmodel.Cookie{
            {Name: "session", Value: "YOUR_SESSION_COOKIE"},
            {Name: "csrf", Value: "YOUR_CSRF_COOKIE"},
        },
    },
}
if errs := services.SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
    for _, err := range errs {
        log.Println("invalid credentials:", err)
    }
    return
}

call := httpmodel.ApiCall{
    CredsId:    "cookie-credential",
    AuthMethod: constants.AM_Cookie,
    Request: httpmodel.Request{
        Method:  "GET",
        BaseUrl: "https://api.example.com",
        Path:    "/protected",
    },
}
response, err := services.MakeApiCall(call)
```

Import `httpmodel "github.com/Anton-Kiptsevich/KipApi/models/http"` for `httpmodel.Cookie`, and initialize the credential service with `services.InitCredsSvc()` once during application startup. Handle `err` and inspect the response status and body as appropriate.

The `Cookies` field accepts multiple cookies. Each cookie has a required, non-empty `Name` and `Value`; optional attributes are `Path`, `Domain`, `Expires`, and `MaxAge`. A cookie cannot set both `Expires` and `MaxAge`, and cookie names must be unique case-insensitively within the same list.

You can also set cookies directly on `httpmodel.Request.Cookies`. If a request cookie and a credential cookie have the same name (case-insensitively), the request cookie takes precedence and the credential cookie with that name is not added. This lets a caller override a stored cookie for an individual request.

KipApi sends the configured cookies with the request; it does not automatically refresh or renew them. Your application is responsible for obtaining updated cookies and updating the stored credentials when needed.

## HMAC authentication

KipApi supports HMAC request signing with SHA-1, SHA-256, SHA-384, and SHA-512. Signatures can be encoded as Base64 or hexadecimal.

Register HMAC credentials using `creds.HMACCreds`:

- `Algorithm`: hash algorithm, such as `constants.HA_SHA256`.
- `SecretKey`: secret key used to calculate the signature.
- `SignatureEncoding`: `base64` or `hex`.
- `SignatureHeaderName`: header that will carry the generated signature.
- `Signature`: template describing the data to sign.
- `PlaceholderCanonicalizationFuncs`: optional functions that transform individual placeholder values before signing.

The signature template supports these placeholders:

| Placeholder | Value |
|---|---|
| `{method}` | HTTP method |
| `{url}` | Full request URL |
| `{baseUrl}` | Base URL |
| `{scheme}` | URL scheme |
| `{host}` | URL hostname |
| `{port}` | URL port |
| `{path}` | URL path |
| `{query}` | URL query string |
| `{body}` | Request body |
| `{contentLength}` | Request body length in bytes |
| `{header:Name}` | Value of a request header |

Use the exact canonicalization format required by the target API. For example, if the API requires the body to be represented by its SHA-256 hash, configure a canonicalization function for `{body}`. Header placeholders must refer to headers present in the request; matching is case-insensitive.

Register the credential with `CredsType: constants.CT_HMAC` and make requests using `AuthMethod: constants.AM_HMAC`. KipApi generates the signature and adds it to `SignatureHeaderName`. If the signature header is already supplied in the request, KipApi preserves it unchanged.

Example:

```go
credential := creds.Creds{
    Id:        "hmac-credential",
    CredsType: constants.CT_HMAC,
    Creds: creds.HMACCreds{
        Algorithm:           constants.HA_SHA256,
        SecretKey:           "YOUR_SECRET_KEY",
        SignatureEncoding:   "hex",
        SignatureHeaderName: "X-Signature",
        Signature:           "{method}\\n{path}\\n{header:X-Timestamp}\\n{body}",
    },
}
if errs := services.SetCreds([]creds.Creds{credential}, false); len(errs) > 0 {
    for _, err := range errs {
        log.Println("invalid credentials:", err)
    }
    return
}

call := httpmodel.ApiCall{
    CredsId:    "hmac-credential",
    AuthMethod: constants.AM_HMAC,
    Request: httpmodel.Request{
        Method:  "POST",
        BaseUrl: "https://api.example.com",
        Path:    "/orders",
        Headers: []httpmodel.Header{
            {Name: "X-Timestamp", Value: &timestamp},
        },
        Body: `{"id":123}`,
    },
}
response, err := services.MakeApiCall(call)
```

Replace the example secret, URL, timestamp, and canonical template with the values and signing rules required by your API. Load secrets from configuration or a secret store rather than hard-coding them in source control.

## Plain HTTP requests

Use `services/base.MakeHttpRequest` when you want HTTP execution without credential lookup or automatic authentication:

```go
import (
    httpmodel "github.com/Anton-Kiptsevich/KipApi/models/http"
    "github.com/Anton-Kiptsevich/KipApi/services/base"
)

response, err := base.MakeHttpRequest(&httpmodel.Request{
    Method:  "GET",
    BaseUrl: "https://api.example.com",
    Path:    "/health",
})
```

Add any required authorization headers yourself. Transport, request-construction, or response-reading failures are returned as Go errors. HTTP statuses such as `401 Unauthorized` and `500 Internal Server Error` are responses, not automatically Go errors; inspect `response.Status` and `response.Body`.

## OAuth 2.0

For automatic refresh, register an OAuth credential with `CredsType: constants.CT_OAuth2` and `Creds: creds.OAuth2Creds{...}`. The model stores `AccessToken`, `RefreshToken`, `ExpirationDate`, `TokenURL`, `ClientID`, and `ClientSecret`.

When `MakeApiCall` uses `constants.AM_Bearer`, KipApi refreshes an OAuth2 token if it has expired or will expire within five seconds. The refreshed credentials are saved to KipApi's in-memory store and marked as needing synchronization with your application's persistent store.

The `services/auth` package also exposes `GetOAuthTokenByPassword` and `RefreshOAuthToken` for direct token requests. These functions return credentials but do not update KipApi's store. If you use them for credentials already registered with KipApi, update both your application's persisted copy and KipApi's in-memory copy (for example, with `SetCreds`) to avoid divergence. Use the password grant only if your identity provider supports it.

## Credential persistence and synchronization

KipApi's credential store is in-memory, not a database. It is cleared when the process restarts; your application owns durable storage.

The second argument to `SetCreds` controls whether the entry should be marked as needing persistence:

- `false`: use when loading credentials that are already persisted by your application.
- `true`: use when adding or updating credentials that still need to be saved by your application.

To synchronize changes, call `GetCredsForSync`, persist each returned entry in your own storage, and call `MarkCredsSynced(id)` only after that save succeeds:

```go
pending := services.GetCredsForSync()
for id, credential := range pending {
    if err := saveCredentialToYourDatabase(id, credential); err != nil {
        // Handle the error and leave this entry pending.
        continue
    }
    if err := services.MarkCredsSynced(id, credential.Version); err != nil {
        // Handle an unknown or outdated credential version.
    }
}
```

`saveCredentialToYourDatabase` is a placeholder for your application's own persistence function, not a KipApi function. Credentials refreshed automatically during `MakeApiCall` are marked as needing synchronization too.

## Public packages

- `constants`: credential types and authentication methods.
- `models/creds`: credential models.
- `models/http`: HTTP request, response, header, and API-call models.
- `services`: credential registration/synchronization and `MakeApiCall`.
- `services/auth`: direct OAuth token helpers and Digest authorization.
- `services/base`: low-level HTTP execution.

The `internal/storage` and `internal/utils` packages are implementation details and cannot be imported by applications outside the KipApi module.

## Responsibility boundary

KipApi handles HTTP execution and common authentication mechanics. Your application handles business logic, API-specific models, endpoint selection, response interpretation, and persistent storage.
