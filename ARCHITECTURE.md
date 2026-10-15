# Architecture

This document defines the allowed Go package dependencies in KipApi. These rules are normative: when adding or moving code, follow them even if another dependency would be convenient.

## Package layout

The `services` directory contains the main service package and specialized implementation packages:

```text
services/                 Go package: services
├── auth_svc.go            Main auth service (auth_svc)
├── http_svc.go            Main HTTP service (http_svc)
├── certificate_svc.go     Example of a possible future main service
├── auth/                  Go package: services/auth
├── http/                  Go package: services/http
├── certificates/          Example of a possible future package
└── base/                  Go package: services/base

internal/
├── storage/
└── utils/
```

Files directly inside `services/` belong to the same Go package, `services`. They are not separate packages merely because they implement different services. In particular, `auth_svc.go` and `http_svc.go` can call each other directly.

Each subdirectory under `services/` is a separate Go package. The package path, not the service's conceptual name, determines Go import dependencies.

## Rule 1: Main services may call each other

The main services live directly in the `services` package. They may call:
- other functions in the `services` package, including other main services;
- their corresponding specialized implementation package;
- packages in `services/base`;
- applicable non-service packages, such as `constants`, `models`, and `internal` packages.

Examples:
- `auth_svc` may call `http_svc`, and `http_svc` may call `auth_svc`;
- `certificate_svc`, if added directly to `services/`, may call both `auth_svc` and `http_svc`;
- `auth_svc` may call `services/auth`;
- `http_svc` may call `services/http`.

Mutual calls between functions in the same Go package do not create an import cycle. Avoid introducing a runtime call loop, but that is separate from package dependency rules.

## Rule 2: Specialized service packages are owned by their corresponding main service

A specialized package under `services/` may be called by its corresponding main service in the root `services` package. Other main services must not call that specialized package directly.

| Specialized package | Allowed caller in the main `services` package |
| --- | --- |
| `services/auth` | `auth_svc` |
| `services/http` | `http_svc` |
| `services/certificates` (if added) | `certificate_svc` |

A specialized service package:
- may depend on `services/base`;
- may depend on non-service packages such as `constants`, `models`, and appropriate `internal` packages;
- must not import the root `services` package;
- must not import another specialized service package under `services/`, including a sibling package;
- must not depend on any other service package except `services/base`.

For example, `services/auth` must not import `services`, `services/http`, or `services/certificates`. If authentication needs functionality provided by another main service, the orchestration belongs in the main `services` package, not in the specialized package.

## Rule 3: `services/base` is the shared low-level service layer

Any main service or specialized service package may depend on `services/base`.

Packages inside `services/base` may depend on other packages inside `services/base` and on non-service packages they need, such as `internal/utils`. They must not import:
- the root `services` package;
- `services/auth`, `services/http`, `services/certificates`, or any other specialized service package.

In short, `services/base` must not depend on any service outside `services/base`.

## Dependency matrix

The following summarizes the service-to-service rules:

| Package making the import | Root `services` | `services/auth` | `services/http` | Other specialized service packages | `services/base` |
| --- | --- | --- | --- | --- | --- |
| Root `services` package | Allowed (same package) | Only through the corresponding main service | Only through the corresponding main service | Only through the corresponding main service | Allowed |
| `services/auth` | Forbidden | Same package | Forbidden | Forbidden | Allowed |
| `services/http` | Forbidden | Forbidden | Same package | Forbidden | Allowed |
| Any other specialized service package | Forbidden | Forbidden | Forbidden | Forbidden | Allowed |
| `services/base` | Forbidden | Forbidden | Forbidden | Forbidden | Allowed (same package or other base packages) |

“Same package” means files share one Go package and no import is needed between them. The matrix concerns imports between service packages; it does not prohibit dependencies on appropriate non-service packages.

## Adding a new service

For a new main service such as `certificate_svc`:

1. Add `certificate_svc.go` directly under `services/`. As part of the root `services` package, it may call `auth_svc`, `http_svc`, and other main services.
2. It may use `services/base` and appropriate non-service packages.
3. If its implementation grows, move cohesive implementation details into `services/certificates/`.
4. Call that specialized package from `certificate_svc`; do not make it import the root `services` package or sibling service packages.
5. Put cross-service orchestration in the root `services` package, not in specialized packages.

## Why these rules exist

The root `services` package is the orchestration layer. Specialized packages implement details for their owning main service. `services/base` contains shared low-level functionality.

This direction keeps specialized implementations independent and prevents Go import cycles. Do not reverse a dependency to reuse code; move shared low-level code into `services/base` or place orchestration in the root `services` package instead.

## Public and internal packages

Packages under `constants`, `models`, and `services` are importable by consumers of KipApi, subject to Go's normal package rules.

Packages under `internal/storage` and `internal/utils` are implementation details. Go prevents code outside the parent module from importing them directly.
