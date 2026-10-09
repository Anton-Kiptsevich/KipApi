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
- `Body`: optional request body as a string.
- `TlsCert`: optional TLS client certificate.

If the request already has an `Authorization` header, KipApi leaves it unchanged. For `AM_Header`, an existing header with the configured `FieldName` is also left unchanged.

### Headers and body

Each `httpmodel.Header` must set exactly one of `Value` or `Values`. Use `Value` for one value and `Values` for multiple values.

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
    if err := services.MarkCredsSynced(id); err != nil {
        // Handle an unknown credential ID.
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
