# Architecture

KipApi uses a layered service architecture.

```text
services
├── auth
├── http
└── base
```

## Package Dependencies

Package dependencies may only go downward.

```text
services → auth
services → http
services → base

auth → base
http → base
```

`base` is the lowest service layer. Packages at any level may depend on `base`.

`base` must not depend on any service layer.

Horizontal package dependencies are forbidden:

```text
auth ✗→ http
http ✗→ auth
```

Sibling packages must remain independent of each other.
