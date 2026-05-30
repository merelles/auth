use std::env;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageDialect {
    Memory,
    Postgres,
    Redis,
    PostgresRedisCache,
    MongoDb,
    MongoDbRedisCache,
}

impl StorageDialect {
    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();
        match env::var("AUTH_STORAGE_DIALECT")
            .unwrap_or_else(|_| "memory".to_string())
            .to_lowercase()
            .as_str()
        {
            "memory" => Self::Memory,
            "postgres" => Self::Postgres,
            "redis" => Self::Redis,
            "postgres_redis_cache" => Self::PostgresRedisCache,
            "mongodb" => Self::MongoDb,
            "mongodb_redis_cache" => Self::MongoDbRedisCache,
            _ => Self::Memory,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthServiceConfig {
    pub host: String,
    pub port: u16,
    pub storage_dialect: StorageDialect,
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
            storage_dialect: StorageDialect::from_env(),
        }
    }
}
