use async_trait::async_trait;
use std::sync::Arc;

use crate::domain::{
    entities::{AccessContext, AuthenticatedSession, Identity},
    errors::AuthError,
};

#[async_trait]
pub trait TokenService: Send + Sync {
    async fn issue_for(&self, identity: Identity) -> Result<AuthenticatedSession, AuthError>;

    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<AuthenticatedSession, AuthError>;

    async fn revoke(&self, access_token: &str) -> Result<(), AuthError>;

    async fn introspect(&self, access_token: &str) -> Result<AccessContext, AuthError>;
}

#[async_trait]
impl<T> TokenService for Arc<T>
where
    T: TokenService + ?Sized,
{
    async fn issue_for(&self, identity: Identity) -> Result<AuthenticatedSession, AuthError> {
        self.as_ref().issue_for(identity).await
    }

    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<AuthenticatedSession, AuthError> {
        self.as_ref().refresh(access_token, refresh_token).await
    }

    async fn revoke(&self, access_token: &str) -> Result<(), AuthError> {
        self.as_ref().revoke(access_token).await
    }

    async fn introspect(&self, access_token: &str) -> Result<AccessContext, AuthError> {
        self.as_ref().introspect(access_token).await
    }
}
