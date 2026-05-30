use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::domain::{entities::AuthSession, errors::AuthError};

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError>;
    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError>;
    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError>;
    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
impl<T> SessionRepository for Arc<T>
where
    T: SessionRepository + ?Sized,
{
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        self.as_ref().save(session).await
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        self.as_ref().find_by_session_id(session_id).await
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        self.as_ref().revoke_by_session_id(session_id).await
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        self.as_ref().revoke_by_subject_id(subject_id).await
    }
}
