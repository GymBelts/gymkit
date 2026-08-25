# gymkit

Shared Go libraries for [GymBelts](https://github.com/GymBelts) apps (AMP, Wodgen, GymAuth).

```
github.com/GymBelts/gymkit
```

This repo is public so those apps can `go get` it. It is **not** a supported third-party library: APIs can change without notice, and there is no stability or support commitment. Fork if you want the code; do not take a dependency expecting it to stay compatible.

## Packages

| Package | Used by | Purpose |
|---|---|---|
| [`oidc`](./oidc) | AMP, Wodgen | OIDC relying-party client (PKCE, token exchange, GymAuth app-user APIs) |
| [`secret`](./secret) | AMP, Wodgen | AES-GCM encrypt/decrypt and secret masking |
| [`impersonate`](./impersonate) | AMP, Wodgen, GymAuth | Gin session middleware: actor vs effective user |

SQL, RBAC policy, HTML banners, start/stop handlers, the GymAuth OIDC *provider*, sessions, and app config stay in each app.

## Use

```bash
go get github.com/GymBelts/gymkit@v0.1.1
```

```go
import (
	"github.com/GymBelts/gymkit/impersonate"
	"github.com/GymBelts/gymkit/oidc"
	"github.com/GymBelts/gymkit/secret"
)
```

GymAuth does not import `oidc` or `secret`.

## License

[MIT](./LICENSE) — you may reuse the code. We still do not recommend depending on this module from outside GymBelts.
