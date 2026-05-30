mod config;

use async_trait::async_trait;
use auth_core::domain::{
    entities::{AuthSession, LoginAttempt},
    errors::AuthError,
    repositories::{LoginAttemptRepository, SessionRepository},
};
use chrono::Utc;
use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use config::RedisConfig;

#[derive(Clone)]
pub struct RedisSessionRepository {
    client: Client,
}

#[derive(Clone)]
pub struct RedisLoginAttemptRepository {
    client: Client,
}

#[derive(Clone)]
pub struct RedisAuthRepositories {
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    session_id: Uuid,
    subject_id: Uuid,
    login: String,
    refresh_token_hash: String,
    issued_at: chrono::DateTime<Utc>,
    access_expires_at: chrono::DateTime<Utc>,
    refresh_expires_at: chrono::DateTime<Utc>,
    revoked_at: Option<chrono::DateTime<Utc>>,
}

impl RedisAuthRepositories {
    pub fn connect(redis_url: &str) -> Result<Self, AuthError> {
        let client = Client::open(redis_url).map_err(|err| {
            AuthError::Infrastructure(format!("unable to connect to redis: {err}"))
        })?;
        Ok(Self { client })
    }

    pub fn from_env() -> Result<Option<Self>, AuthError> {
        match RedisConfig::from_env() {
            Some(config) => Self::connect(&config.redis_url).map(Some),
            None => Ok(None),
        }
    }

    pub fn sessions(&self) -> RedisSessionRepository {
        RedisSessionRepository {
            client: self.client.clone(),
        }
    }

    pub fn login_attempts(&self) -> RedisLoginAttemptRepository {
        RedisLoginAttemptRepository {
            client: self.client.clone(),
        }
    }
}

fn session_key(session_id: Uuid) -> String {
    format!("auth:sessions:{session_id}")
}

fn subject_sessions_key(subject_id: Uuid) -> String {
    format!("auth:subject-sessions:{subject_id}")
}

#[async_trait]
impl SessionRepository for RedisSessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to open redis connection: {err}"))
            })?;
        let payload = serde_json::to_string(&StoredSession {
            session_id: session.session_id,
            subject_id: session.subject_id,
            login: session.login.clone(),
            refresh_token_hash: session.refresh_token_hash.clone(),
            issued_at: session.issued_at,
            access_expires_at: session.access_expires_at,
            refresh_expires_at: session.refresh_expires_at,
            revoked_at: session.revoked_at,
        })
        .map_err(|err| {
            AuthError::Infrastructure(format!("unable to serialize redis session: {err}"))
        })?;
        let ttl = (session.refresh_expires_at - Utc::now())
            .num_seconds()
            .max(1) as u64;
        let _: () = connection
            .set_ex(session_key(session.session_id), payload, ttl)
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to store session in redis: {err}"))
            })?;
        let _: () = connection
            .sadd(
                subject_sessions_key(session.subject_id),
                session.session_id.to_string(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to index redis session: {err}"))
            })?;
        let _: () = connection
            .expire(subject_sessions_key(session.subject_id), ttl as i64)
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to expire redis subject index: {err}"))
            })?;
        Ok(())
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to open redis connection: {err}"))
            })?;
        let payload: Option<String> =
            connection
                .get(session_key(session_id))
                .await
                .map_err(|err| {
                    AuthError::Infrastructure(format!("unable to fetch session from redis: {err}"))
                })?;
        payload
            .map(|value| {
                serde_json::from_str::<StoredSession>(&value)
                    .map(|stored| AuthSession {
                        session_id: stored.session_id,
                        subject_id: stored.subject_id,
                        login: stored.login,
                        refresh_token_hash: stored.refresh_token_hash,
                        issued_at: stored.issued_at,
                        access_expires_at: stored.access_expires_at,
                        refresh_expires_at: stored.refresh_expires_at,
                        revoked_at: stored.revoked_at,
                    })
                    .map_err(|err| {
                        AuthError::Infrastructure(format!(
                            "unable to deserialize redis session: {err}"
                        ))
                    })
            })
            .transpose()
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        let Some(mut session) = self.find_by_session_id(session_id).await? else {
            return Ok(());
        };
        session.revoked_at = Some(Utc::now());
        self.save(session).await
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to open redis connection: {err}"))
            })?;
        let session_ids: Vec<String> = connection
            .smembers(subject_sessions_key(subject_id))
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to list subject sessions: {err}"))
            })?;
        for raw in session_ids {
            if let Ok(session_id) = Uuid::parse_str(&raw) {
                self.revoke_by_session_id(session_id).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for RedisLoginAttemptRepository {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        let mut connection = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to open redis connection: {err}"))
            })?;
        let payload = serde_json::to_string(&attempt).map_err(|err| {
            AuthError::Infrastructure(format!("unable to serialize login attempt: {err}"))
        })?;
        let key = format!("auth:login-attempts:{}", attempt.login);
        let _: () = connection.lpush(&key, payload).await.map_err(|err| {
            AuthError::Infrastructure(format!("unable to persist login attempt: {err}"))
        })?;
        let _: () = connection.ltrim(&key, 0, 199).await.map_err(|err| {
            AuthError::Infrastructure(format!("unable to trim login attempts: {err}"))
        })?;
        let _: () = connection
            .expire(&key, 60 * 60 * 24 * 30)
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to expire login attempts: {err}"))
            })?;
        Ok(())
    }
}
