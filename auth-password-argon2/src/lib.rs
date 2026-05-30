mod config;

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use async_trait::async_trait;
use auth_core::domain::{errors::AuthError, services::PasswordService};
use rand_core::OsRng;

pub use config::Argon2PasswordConfig;

#[derive(Debug, Clone)]
pub struct Argon2PasswordService {
    config: Argon2PasswordConfig,
}

impl Argon2PasswordService {
    pub fn new(config: Argon2PasswordConfig) -> Self {
        Self { config }
    }

    fn build_hasher(&self) -> Result<Argon2<'static>, AuthError> {
        let params = Params::new(
            self.config.memory_kib,
            self.config.iterations,
            self.config.parallelism,
            None,
        )
        .map_err(|err| AuthError::Configuration(format!("invalid argon2 params: {err}")))?;

        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    fn peppered_password<'a>(&'a self, raw_password: &'a str) -> Vec<u8> {
        match self.config.pepper.as_deref() {
            Some(pepper) => {
                let mut combined = Vec::with_capacity(raw_password.len() + pepper.len());
                combined.extend_from_slice(raw_password.as_bytes());
                combined.extend_from_slice(pepper.as_bytes());
                combined
            }
            None => raw_password.as_bytes().to_vec(),
        }
    }
}

impl Default for Argon2PasswordService {
    fn default() -> Self {
        Self::new(Argon2PasswordConfig::default())
    }
}

#[async_trait]
impl PasswordService for Argon2PasswordService {
    async fn hash(&self, raw_password: &str) -> Result<String, AuthError> {
        let salt = SaltString::generate(&mut OsRng);
        let password = self.peppered_password(raw_password);
        let hasher = self.build_hasher()?;

        hasher
            .hash_password(&password, &salt)
            .map(|hash| hash.to_string())
            .map_err(|err| AuthError::Infrastructure(format!("unable to hash password: {err}")))
    }

    async fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|err| AuthError::Infrastructure(format!("invalid password hash: {err}")))?;
        let password = self.peppered_password(raw_password);
        let hasher = self.build_hasher()?;

        Ok(hasher.verify_password(&password, &parsed_hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::{Argon2PasswordConfig, Argon2PasswordService};
    use auth_core::domain::services::PasswordService;

    #[tokio::test]
    async fn hashes_and_verifies_passwords() {
        let service = Argon2PasswordService::default();

        let hash = service.hash("senha-segura").await.unwrap();

        assert!(hash.starts_with("$argon2id$"));
        assert!(service.verify("senha-segura", &hash).await.unwrap());
        assert!(!service.verify("senha-invalida", &hash).await.unwrap());
    }

    #[tokio::test]
    async fn pepper_changes_verification_context() {
        let service = Argon2PasswordService::new(
            Argon2PasswordConfig::recommended().with_pepper("pepper-super-secreto"),
        );
        let same_params_without_pepper =
            Argon2PasswordService::new(Argon2PasswordConfig::recommended());

        let hash = service.hash("senha-segura").await.unwrap();

        assert!(service.verify("senha-segura", &hash).await.unwrap());
        assert!(!same_params_without_pepper
            .verify("senha-segura", &hash)
            .await
            .unwrap());
    }
}
