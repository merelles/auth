use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::{entities::LoginAttempt, errors::AuthError};

#[async_trait]
pub trait LoginAttemptRepository: Send + Sync {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError>;
}

#[async_trait]
impl<T> LoginAttemptRepository for Arc<T>
where
    T: LoginAttemptRepository + ?Sized,
{
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        self.as_ref().record(attempt).await
    }
}
