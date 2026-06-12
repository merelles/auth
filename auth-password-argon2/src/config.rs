use std::env;

#[derive(Debug, Clone)]
pub struct Argon2PasswordConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub pepper: Option<String>,
}

impl Argon2PasswordConfig {
    pub fn recommended() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
            pepper: None,
        }
    }

    pub fn with_pepper(mut self, pepper: impl Into<String>) -> Self {
        self.pepper = Some(pepper.into());
        self
    }

    pub fn from_env() -> Self {
        let _ = dotenvy::dotenv();

        Self {
            memory_kib: env::var("AUTH_PASSWORD_MEMORY_KIB")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(65_536),
            iterations: env::var("AUTH_PASSWORD_ITERATIONS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(3),
            parallelism: env::var("AUTH_PASSWORD_PARALLELISM")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(1),
            pepper: Some(env::var("AUTH_PASSWORD_PEPPER").unwrap_or_else(|_| "m".to_string())),
        }
    }
}

impl Default for Argon2PasswordConfig {
    fn default() -> Self {
        Self::recommended()
    }
}

#[cfg(test)]
mod tests {
    use super::Argon2PasswordConfig;
    use std::{
        env,
        sync::{Mutex, OnceLock},
    };

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_auth_password_env() {
        unsafe {
            env::remove_var("AUTH_PASSWORD_MEMORY_KIB");
            env::remove_var("AUTH_PASSWORD_ITERATIONS");
            env::remove_var("AUTH_PASSWORD_PARALLELISM");
            env::remove_var("AUTH_PASSWORD_PEPPER");
        }
    }

    #[test]
    fn from_env_uses_defaults_when_variables_are_missing() {
        let _guard = env_lock().lock().unwrap();
        clear_auth_password_env();

        let config = Argon2PasswordConfig::from_env();

        assert_eq!(config.memory_kib, 65_536);
        assert_eq!(config.iterations, 3);
        assert_eq!(config.parallelism, 1);
        assert_eq!(config.pepper.as_deref(), Some("m"));
    }

    #[test]
    fn from_env_reads_explicit_values() {
        let _guard = env_lock().lock().unwrap();
        clear_auth_password_env();

        unsafe {
            env::set_var("AUTH_PASSWORD_MEMORY_KIB", "32768");
            env::set_var("AUTH_PASSWORD_ITERATIONS", "4");
            env::set_var("AUTH_PASSWORD_PARALLELISM", "2");
            env::set_var("AUTH_PASSWORD_PEPPER", "pepper-de-teste");
        }

        let config = Argon2PasswordConfig::from_env();

        assert_eq!(config.memory_kib, 32_768);
        assert_eq!(config.iterations, 4);
        assert_eq!(config.parallelism, 2);
        assert_eq!(config.pepper.as_deref(), Some("pepper-de-teste"));

        clear_auth_password_env();
    }
}
