# central-auth

Internal authentication microservice — issues and validates signed JWT access/refresh token pairs for trusted backend services over a shared API key.

## Core Structs

| Struct | Package | Responsibility |
|---|---|---|
| `AuthHandler` | `internal/http/handler` | Binds HTTP requests, translates service errors to 401 vs 500 |
| `AuthService` | `internal/service` | Orchestrates login, logout, refresh, and session verification |
| `Claims` | `internal/token` | JWT payload — `user_id`, `device_id`, `token_type`, `exp`, `iat` |
| `RedisRepository` | `internal/repository` | Live session state — stores, rotates, validates, and revokes refresh tokens |
| `PostgresAuthUserRepository` | `internal/repository` | Audit store — user identity, token hashes, device history, revocation |
| `AuthUser` | `internal/domain` | OAuth user record keyed on `(provider, provider_user_id)` |
| `RefreshToken` | `internal/domain` | Audit row — token hash, device metadata, `last_used_at`, revoked flag |
| `ServiceAuthMiddleware` | `internal/http/middleware` | Guards all `/auth` routes via constant-time `X-Service-Key` comparison |

