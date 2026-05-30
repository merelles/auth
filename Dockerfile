# syntax=docker/dockerfile:1

FROM rust:1.88-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY auth-client ./auth-client
COPY auth-client-http ./auth-client-http
COPY auth-core ./auth-core
COPY auth-middleware-actix ./auth-middleware-actix
COPY auth-password-argon2 ./auth-password-argon2
COPY auth-repo-cache ./auth-repo-cache
COPY auth-repo-memory ./auth-repo-memory
COPY auth-repo-postgres ./auth-repo-postgres
COPY auth-repo-redis ./auth-repo-redis
COPY auth-service ./auth-service
COPY auth-token-jwt ./auth-token-jwt

RUN cargo build --release -p auth-service

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service

EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/auth-service"]
