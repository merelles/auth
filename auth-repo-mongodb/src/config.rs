use std::env;

#[derive(Debug, Clone)]
pub struct MongoConfig {
    pub uri: String,
    pub database: String,
}

impl MongoConfig {
    pub fn from_env() -> Option<Self> {
        let _ = dotenvy::dotenv();
        let uri = env::var("AUTH_MONGODB_URI")
            .or_else(|_| env::var("MONGODB_URI"))
            .ok()?;
        let database = env::var("AUTH_MONGODB_DATABASE")
            .unwrap_or_else(|_| "auth".to_string());

        Some(Self { uri, database })
    }
}
