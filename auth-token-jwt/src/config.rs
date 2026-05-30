use std::env;

#[derive(Debug, Clone)]
pub struct JwtTokenConfig {
    pub issuer: String,
    pub secret: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_seconds: i64,
}

impl JwtTokenConfig {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        Self {
            issuer: env::var("AUTH_JWT_ISSUER").unwrap_or_else(|_| "auth-service".to_string()),
            secret: env::var("AUTH_JWT_SECRET").unwrap_or_else(|_| "change-me".to_string()),
            access_ttl_seconds: env::var("AUTH_JWT_ACCESS_TTL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(900),
            refresh_ttl_seconds: env::var("AUTH_JWT_REFRESH_TTL_SECONDS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(86_400),
        }
    }
}
