# Architecture

KipApi uses a layered service architecture.

```text
services
├── auth
├── base
└── root service functions

internal
├── storage
└── utils
```

## Package Dependencies

Package dependencies may only go downward.

```text
services → auth
services → base
services → internal/storage
services → internal/utils

auth → base
base → internal/utils
```

`base` is the lowest service layer. Packages at any level may depend on `base`.

`base` must not depend on any service layer.

Horizontal package dependencies are forbidden:

```text
auth ✗→ services
auth ✗→ other sibling service packages
```

Sibling packages must remain independent of each other.

## Public and internal packages

The packages under `constants`, `models`, and `services` remain importable by consumers of KipApi.

The `internal/storage` and `internal/utils` packages are implementation details. Go prevents code outside the parent module from importing them directly.
