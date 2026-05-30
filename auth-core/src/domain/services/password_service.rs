use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::errors::AuthError;

#[async_trait]
pub trait PasswordService: Send + Sync {
    async fn hash(&self, raw_password: &str) -> Result<String, AuthError>;

    async fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError>;
}

#[async_trait]
impl<T> PasswordService for Arc<T>
where
    T: PasswordService + ?Sized,
{
    async fn hash(&self, raw_password: &str) -> Result<String, AuthError> {
        self.as_ref().hash(raw_password).await
    }

    async fn verify(&self, raw_password: &str, password_hash: &str) -> Result<bool, AuthError> {
        self.as_ref().verify(raw_password, password_hash).await
    }
}
