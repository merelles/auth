use std::env;

#[derive(Debug, Clone)]
pub struct AuthServiceConfig {
    pub host: String,
    pub port: u16,
}

impl AuthServiceConfig {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        Self {
            host: env::var("AUTH_SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("AUTH_SERVER_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(9090),
        }
    }
}
