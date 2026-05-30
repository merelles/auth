use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::{entities::Identity, errors::AuthError};

#[async_trait]
pub trait IdentityRepository: Send + Sync {
    async fn find_by_id(&self, identity_id: uuid::Uuid) -> Result<Option<Identity>, AuthError>;
    async fn find_by_login(&self, login: &str) -> Result<Option<Identity>, AuthError>;
    async fn create(&self, identity: Identity) -> Result<Identity, AuthError>;
}

#[async_trait]
impl<T> IdentityRepository for Arc<T>
where
    T: IdentityRepository + ?Sized,
{
    async fn find_by_id(&self, identity_id: uuid::Uuid) -> Result<Option<Identity>, AuthError> {
        self.as_ref().find_by_id(identity_id).await
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<Identity>, AuthError> {
        self.as_ref().find_by_login(login).await
    }

    async fn create(&self, identity: Identity) -> Result<Identity, AuthError> {
        self.as_ref().create(identity).await
    }
}
