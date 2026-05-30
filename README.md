# auth
`auth` is a Rust workspace for authentication and identity, designed with a modular architecture, production-ready HTTP service, multiple persistence backends, and reusable integration components.

## Overview
- HTTP service built with `actix-web` and OpenAPI/Swagger docs.
- Full authentication flow: register, login, refresh, revoke, and introspect.
- JWT token lifecycle with persisted sessions and token revocation.
- Argon2id password hashing and verification.
- Repository implementations for `memory`, `postgres`, `redis`, and `mongodb`.
- Hybrid cache dialects using Redis (`postgres_redis_cache` and `mongodb_redis_cache`).
- Reusable Actix middleware and both in-process/HTTP clients.

## Workspace Architecture

### Domain Core
- `auth-core`: entities, commands, errors, repository traits, and use cases.

### Service and Integration
- `auth-service`: HTTP API and use-case composition.
- `auth-client`: client contract plus in-process implementation.
- `auth-client-http`: HTTP client for remote `auth-service` consumption.
- `auth-middleware-actix`: middleware to protect Actix endpoints.

### Security
- `auth-token-jwt`: JWT issue/refresh/introspect/revoke operations.
- `auth-password-argon2`: Argon2id password hashing and verification.

### Persistence
- `auth-repo-memory`: in-memory repositories.
- `auth-repo-postgres`: PostgreSQL repositories.
- `auth-repo-redis`: Redis repositories/cache.
- `auth-repo-mongodb`: MongoDB repositories.
- `auth-repo-cache`: cache wrappers with source-of-truth persistence.

## Features
- Identity registration (`login`, `email`, `password`).
- Login with `access_token` and `refresh_token` issuance.
- Session refresh with token renewal.
- Session/token revocation.
- Service-to-service token introspection.
- Login-attempt recording.
- Runtime storage backend selection via environment variables.

## HTTP Endpoints
- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/revoke`
- `POST /auth/introspect`
- `GET /swagger-ui/`
- `GET /api-docs/openapi.json`

## Storage Dialect
Primary backend selection is controlled by `AUTH_STORAGE_DIALECT`:

- `memory`: all repositories in memory.
- `postgres`: identities/sessions/login attempts in PostgreSQL.
- `redis`: sessions/login attempts in Redis (identities in memory).
- `postgres_redis_cache`: PostgreSQL as source of truth + Redis cache for sessions and login attempts.
- `mongodb`: identities/sessions/login attempts in MongoDB.
- `mongodb_redis_cache`: MongoDB as source of truth + Redis cache for sessions and login attempts.

## Environment Variables
See [`.env.example`](C:/Users/leona/RustroverProjects/auth/.env.example) for a complete template.

### Service
- `AUTH_SERVER_HOST` (default: `0.0.0.0`)
- `AUTH_SERVER_PORT` (default: `9090`)
- `AUTH_STORAGE_DIALECT` (default: `memory`)

### PostgreSQL (when applicable)
- `AUTH_DATABASE_HOST`
- `AUTH_DATABASE_PORT`
- `AUTH_DATABASE_NAME`
- `AUTH_DATABASE_USER`
- `AUTH_DATABASE_PASSWORD`

### Redis (when applicable)
- `REDIS_URL`

### MongoDB (when applicable)
- `AUTH_MONGODB_URI` (fallback: `MONGODB_URI`)
- `AUTH_MONGODB_DATABASE` (default: `auth`)

### JWT / Security
JWT and Argon2 settings are read by the security crates and can be overridden via environment variables.

## Local Development
Prerequisites:
- Stable Rust toolchain (compatible with `edition = 2024`)
- Cargo

Commands:

```bash
cargo check --workspace
cargo test --workspace
cargo run -p auth-service
```

Default runtime URLs:
- API: `http://localhost:9090`
- Swagger UI: `http://localhost:9090/swagger-ui/`

## Docker
Files:
- `Dockerfile`: multi-stage build with a distroless non-root runtime image.
- `docker-compose.yml`: local stack for `auth-service`.

Container hardening for `auth-service`:
- non-root user
- `cap_drop: ALL`
- `no-new-privileges`
- read-only filesystem
- `tmpfs` mounted for `/tmp`

Run:

```bash
docker compose up --build -d
```

## Cross-Project Integration
- Prefer dependency management via `Cargo.toml` (`git`/tag) or HTTP consumption via `auth-client-http`.
- Avoid direct source-code imports across repositories.
- For strong domain isolation, use `auth-service` as the boundary and expose only HTTP/OpenAPI contracts.

## Engineering Notes
- Workspace follows a ports/adapters style.
- Use cases are decoupled from infrastructure.
- Storage backends and auth mechanisms can be extended incrementally.
- Natural next steps: tracing/metrics, rate limiting, and external secret management (Vault/KMS).

## License
Dual-licensed under:
- MIT
- Apache-2.0
