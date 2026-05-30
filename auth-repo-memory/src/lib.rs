use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use auth_core::domain::{
    entities::{AuthSession, Identity, LoginAttempt},
    errors::AuthError,
    repositories::{IdentityRepository, LoginAttemptRepository, SessionRepository},
};
use chrono::Utc;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct InMemoryIdentityRepository {
    state: Arc<Mutex<IdentityState>>,
}

#[derive(Debug, Default)]
struct IdentityState {
    identities: HashMap<Uuid, Identity>,
    login_index: HashMap<String, Uuid>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemorySessionRepository {
    state: Arc<Mutex<HashMap<Uuid, AuthSession>>>,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryLoginAttemptRepository {
    state: Arc<Mutex<Vec<LoginAttempt>>>,
}

#[async_trait]
impl IdentityRepository for InMemoryIdentityRepository {
    async fn find_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AuthError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("identity repository lock poisoned".into()))?;
        Ok(state.identities.get(&identity_id).cloned())
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<Identity>, AuthError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("identity repository lock poisoned".into()))?;
        Ok(state
            .login_index
            .get(login)
            .and_then(|identity_id| state.identities.get(identity_id))
            .cloned())
    }

    async fn create(&self, identity: Identity) -> Result<Identity, AuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("identity repository lock poisoned".into()))?;

        if state.login_index.contains_key(&identity.login) {
            return Err(AuthError::IdentityAlreadyExists);
        }

        state
            .login_index
            .insert(identity.login.clone(), identity.id);
        state.identities.insert(identity.id, identity.clone());
        Ok(identity)
    }
}

#[async_trait]
impl SessionRepository for InMemorySessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("session repository lock poisoned".into()))?;
        state.insert(session.session_id, session);
        Ok(())
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        let state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("session repository lock poisoned".into()))?;
        Ok(state.get(&session_id).cloned())
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("session repository lock poisoned".into()))?;
        if let Some(session) = state.get_mut(&session_id) {
            session.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AuthError::Infrastructure("session repository lock poisoned".into()))?;
        for session in state.values_mut() {
            if session.subject_id == subject_id {
                session.revoked_at = Some(Utc::now());
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for InMemoryLoginAttemptRepository {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        let mut state = self.state.lock().map_err(|_| {
            AuthError::Infrastructure("login attempt repository lock poisoned".into())
        })?;
        state.push(attempt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InMemoryIdentityRepository, InMemoryLoginAttemptRepository, InMemorySessionRepository,
    };
    use auth_core::domain::{
        entities::{AuthSession, Identity, LoginAttempt},
        repositories::{IdentityRepository, LoginAttemptRepository, SessionRepository},
    };
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn sample_identity() -> Identity {
        Identity {
            id: Uuid::new_v4(),
            login: "tester".to_string(),
            email: Some("tester@example.com".to_string()),
            password_hash: "hash".to_string(),
            active: true,
        }
    }

    #[tokio::test]
    async fn creates_and_reads_identity_by_login() {
        let repository = InMemoryIdentityRepository::default();
        let identity = sample_identity();
        repository.create(identity.clone()).await.unwrap();
        let found = repository.find_by_login("tester").await.unwrap().unwrap();
        assert_eq!(found.id, identity.id);
    }

    #[tokio::test]
    async fn stores_and_revokes_session() {
        let repository = InMemorySessionRepository::default();
        let session_id = Uuid::new_v4();
        repository
            .save(AuthSession {
                session_id,
                subject_id: Uuid::new_v4(),
                login: "tester".into(),
                refresh_token_hash: "hash".into(),
                issued_at: Utc::now(),
                access_expires_at: Utc::now() + Duration::minutes(15),
                refresh_expires_at: Utc::now() + Duration::days(7),
                revoked_at: None,
            })
            .await
            .unwrap();
        repository.revoke_by_session_id(session_id).await.unwrap();
        assert!(repository
            .find_by_session_id(session_id)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some());
    }

    #[tokio::test]
    async fn records_login_attempts() {
        let repository = InMemoryLoginAttemptRepository::default();
        repository
            .record(LoginAttempt {
                attempt_id: Uuid::new_v4(),
                login: "tester".into(),
                successful: false,
                attempted_at: Utc::now(),
            })
            .await
            .unwrap();
    }
}
