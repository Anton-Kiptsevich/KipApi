# KipApi

KipApi is a Go library for simplifying integrations with external HTTP APIs.

It provides reusable infrastructure for:

- HTTP requests and responses;
- credentials management;
- authentication;
- OAuth 2.0 token refresh;
- Digest authentication;
- mTLS;
- reusable HTTP request flows.

KipApi does not implement business logic or clients for specific services. It provides the common infrastructure required to build them.

---

## Core Concept

An integration typically consists of:

```text
Application
    │
    ▼
  KipApi
    │
    ├── Credentials
    ├── Authentication
    └── HTTP request
            │
            ▼
      External API
```

The application defines what it wants to do.

KipApi handles the common mechanics required to communicate with the external API.

---

## Authentication

KipApi separates **credential type** from **authentication method**.

Credential types describe what credentials are available:

```text
Basic
Bearer
OAuth 2.0
API Key
Digest
mTLS
```

Authentication methods describe how credentials are applied to a request:

```text
Basic
Bearer
Header
Query
Digest
mTLS
```

For example, OAuth 2.0 credentials are used to obtain an access token, which is then sent using Bearer authentication.

This separation allows authentication logic to remain independent from individual integrations.

---

## Making a Request

An API call contains the HTTP request and the information required to authenticate it:

```go
call := http.ApiCall{
    CredsId:    "550e8400-e29b-41d4-a716-446655440000",
    AuthMethod: constants.AM_Bearer,
    Request: http.Request{
        Method:  "GET",
        BaseUrl: "https://api.example.com",
        Path:    "/users",
    },
}
```

`CredsId` identifies the credentials to use for the API call.

KipApi handles the authentication and HTTP execution required to perform the call.

The application receives the resulting HTTP status, headers, and body.

---

## Responsibility Boundary

KipApi is responsible for common integration mechanics:

```text
HTTP
Authentication
Credentials
TLS
Request execution
```

The application is responsible for integration-specific logic:

```text
Business logic
Entity mapping
API-specific models
Endpoint selection
Response interpretation
```

For example, KipApi can send a request to create a user, but it does not decide when or why that user should be created.

---

## Design Goal

> **KipApi handles integration mechanics. The application handles integration logic.**
