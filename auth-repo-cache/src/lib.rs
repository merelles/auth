use async_trait::async_trait;
use auth_core::domain::{
    entities::{AuthSession, LoginAttempt},
    errors::AuthError,
    repositories::{LoginAttemptRepository, SessionRepository},
};
use uuid::Uuid;

#[derive(Clone)]
pub struct CachedSessionRepository<C, D> {
    inner: C,
    db: D,
}

impl<C, D> CachedSessionRepository<C, D> {
    pub fn new(inner: C, db: D) -> Self {
        Self { inner, db }
    }
}

#[async_trait]
impl<C, D> SessionRepository for CachedSessionRepository<C, D>
where
    C: SessionRepository + Send + Sync,
    D: SessionRepository + Send + Sync,
{
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        self.db.save(session.clone()).await?;
        self.inner.save(session).await
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        if let Some(session) = self.inner.find_by_session_id(session_id).await? {
            return Ok(Some(session));
        }

        let session = self.db.find_by_session_id(session_id).await?;
        if let Some(ref value) = session {
            self.inner.save(value.clone()).await?;
        }
        Ok(session)
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        self.db.revoke_by_session_id(session_id).await?;
        self.inner.revoke_by_session_id(session_id).await
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        self.db.revoke_by_subject_id(subject_id).await?;
        self.inner.revoke_by_subject_id(subject_id).await
    }
}

#[derive(Clone)]
pub struct CachedLoginAttemptRepository<C, D> {
    inner: C,
    db: D,
}

impl<C, D> CachedLoginAttemptRepository<C, D> {
    pub fn new(inner: C, db: D) -> Self {
        Self { inner, db }
    }
}

#[async_trait]
impl<C, D> LoginAttemptRepository for CachedLoginAttemptRepository<C, D>
where
    C: LoginAttemptRepository + Send + Sync,
    D: LoginAttemptRepository + Send + Sync,
{
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        self.db.record(attempt.clone()).await?;
        self.inner.record(attempt).await
    }
}
