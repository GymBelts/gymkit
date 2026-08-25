# gymkit

Shared Go libraries for GymBelts apps (AMP, Wodgen, GymAuth).

| Package | Used by | Purpose |
|---|---|---|
| `oidc` | AMP, Wodgen | OIDC relying-party client (PKCE, token exchange, app-user APIs) |
| `secret` | AMP, Wodgen | AES-GCM encrypt/decrypt and secret masking |
| `impersonate` | AMP, Wodgen, GymAuth | Gin session middleware: actor vs effective user |

SQL, RBAC policy, banners, and start/stop handlers stay in each app.
