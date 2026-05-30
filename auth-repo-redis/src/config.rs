use std::env;

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub redis_url: String,
}

impl RedisConfig {
    pub fn from_env() -> Option<Self> {
        let _ = dotenvy::dotenv();
        env::var("REDIS_URL")
            .ok()
            .map(|redis_url| Self { redis_url })
    }
}
