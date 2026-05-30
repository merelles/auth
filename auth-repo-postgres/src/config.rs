use std::env;

use tokio_postgres::Config;

#[derive(Debug, Clone)]
pub struct AuthDatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
    pub user: String,
    pub password: String,
}

impl AuthDatabaseConfig {
    pub fn from_env() -> Option<Self> {
        let _ = dotenvy::dotenv();

        Self::from_split_env().or_else(Self::from_database_url_env)
    }

    pub fn postgres_config(&self) -> Config {
        let mut config = Config::new();
        config.host(&self.host);
        config.port(self.port);
        config.dbname(&self.name);
        config.user(&self.user);
        config.password(&self.password);
        config
    }

    fn from_split_env() -> Option<Self> {
        Some(Self {
            host: env::var("AUTH_DATABASE_HOST").ok()?,
            port: env::var("AUTH_DATABASE_PORT").ok()?.parse().ok()?,
            name: env::var("AUTH_DATABASE_NAME").ok()?,
            user: env::var("AUTH_DATABASE_USER").ok()?,
            password: env::var("AUTH_DATABASE_PASSWORD").ok()?,
        })
    }

    fn from_database_url_env() -> Option<Self> {
        let database_url = env::var("AUTH_DATABASE_URL").ok()?;
        let database_url = database_url.strip_prefix("postgres://")?;

        let (credentials, host_and_db) = database_url.split_once('@')?;
        let (user, password) = credentials.split_once(':')?;
        let (host_and_port, name) = host_and_db.split_once('/')?;
        let (host, port) = host_and_port.split_once(':')?;

        Some(Self {
            host: host.to_string(),
            port: port.parse().ok()?,
            name: name.to_string(),
            user: user.to_string(),
            password: password.to_string(),
        })
    }
}
