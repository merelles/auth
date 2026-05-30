mod config;

use async_trait::async_trait;
use auth_core::domain::{
    entities::{AuthSession, Identity, LoginAttempt},
    errors::AuthError,
    repositories::{IdentityRepository, LoginAttemptRepository, SessionRepository},
};
use chrono::Utc;
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::{Config, NoTls, Row};
use uuid::Uuid;

pub use config::AuthDatabaseConfig;

#[derive(Clone)]
pub struct PostgresIdentityRepository {
    pool: Pool,
}

#[derive(Clone)]
pub struct PostgresSessionRepository {
    pool: Pool,
}

#[derive(Clone)]
pub struct PostgresLoginAttemptRepository {
    pool: Pool,
}

#[derive(Clone)]
pub struct PostgresAuthRepositories {
    pool: Pool,
}

impl PostgresAuthRepositories {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub async fn connect(config: &Config) -> Result<Self, AuthError> {
        let manager = Manager::from_config(
            config.clone(),
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );

        let pool = Pool::builder(manager)
            .max_size(16)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to create postgres pool: {err}"))
            })?;

        let _ = pool.get().await.map_err(|err| {
            AuthError::Infrastructure(format!("unable to connect to postgres: {err}"))
        })?;

        Ok(Self::new(pool))
    }

    pub async fn from_env() -> Result<Option<Self>, AuthError> {
        match AuthDatabaseConfig::from_env() {
            Some(config) => Self::connect(&config.postgres_config()).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn ensure_schema(&self) -> Result<(), AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        client
            .batch_execute(
                r#"
                CREATE SCHEMA IF NOT EXISTS auth;

                CREATE TABLE IF NOT EXISTS auth.identities (
                    id UUID PRIMARY KEY,
                    login VARCHAR(255) NOT NULL UNIQUE,
                    email VARCHAR(255) NULL,
                    password_hash TEXT NOT NULL,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth.login_attempts (
                    attempt_id UUID PRIMARY KEY,
                    login VARCHAR(255) NOT NULL,
                    successful BOOLEAN NOT NULL,
                    attempted_at TIMESTAMPTZ NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth.sessions (
                    session_id UUID PRIMARY KEY,
                    subject_id UUID NOT NULL,
                    login VARCHAR(255) NOT NULL,
                    refresh_token_hash TEXT NOT NULL,
                    issued_at TIMESTAMPTZ NOT NULL,
                    access_expires_at TIMESTAMPTZ NOT NULL,
                    refresh_expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ NULL
                );

                CREATE INDEX IF NOT EXISTS idx_auth_identities_login
                    ON auth.identities (login);
                CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_login
                    ON auth.login_attempts (login, attempted_at DESC);
                CREATE INDEX IF NOT EXISTS idx_auth_sessions_subject_id
                    ON auth.sessions (subject_id);
                "#,
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to ensure auth schema: {err}"))
            })
    }

    pub fn identities(&self) -> PostgresIdentityRepository {
        PostgresIdentityRepository {
            pool: self.pool.clone(),
        }
    }

    pub fn sessions(&self) -> PostgresSessionRepository {
        PostgresSessionRepository {
            pool: self.pool.clone(),
        }
    }

    pub fn login_attempts(&self) -> PostgresLoginAttemptRepository {
        PostgresLoginAttemptRepository {
            pool: self.pool.clone(),
        }
    }
}

fn map_identity(row: &Row) -> Identity {
    Identity {
        id: row.get("id"),
        login: row.get("login"),
        email: row.get("email"),
        password_hash: row.get("password_hash"),
        active: row.get("active"),
    }
}

fn map_session(row: &Row) -> AuthSession {
    AuthSession {
        session_id: row.get("session_id"),
        subject_id: row.get("subject_id"),
        login: row.get("login"),
        refresh_token_hash: row.get("refresh_token_hash"),
        issued_at: row.get("issued_at"),
        access_expires_at: row.get("access_expires_at"),
        refresh_expires_at: row.get("refresh_expires_at"),
        revoked_at: row.get("revoked_at"),
    }
}

#[async_trait]
impl IdentityRepository for PostgresIdentityRepository {
    async fn find_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        let row = client
            .query_opt(
                "SELECT id, login, email, password_hash, active FROM auth.identities WHERE id = $1",
                &[&identity_id],
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to query identity by id: {err}"))
            })?;

        Ok(row.as_ref().map(map_identity))
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<Identity>, AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        let row = client.query_opt(
            "SELECT id, login, email, password_hash, active FROM auth.identities WHERE login = $1",
            &[&login],
        ).await.map_err(|err| AuthError::Infrastructure(format!("unable to query identity by login: {err}")))?;

        Ok(row.as_ref().map(map_identity))
    }

    async fn create(&self, identity: Identity) -> Result<Identity, AuthError> {
        let now = Utc::now();
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        let row = client.query_one(
            r#"
            INSERT INTO auth.identities (id, login, email, password_hash, active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, login, email, password_hash, active
            "#,
            &[&identity.id, &identity.login, &identity.email, &identity.password_hash, &identity.active, &now, &now],
        ).await.map_err(|err| {
            if let Some(db_error) = err.as_db_error() {
                if db_error.code().code() == "23505" {
                    return AuthError::IdentityAlreadyExists;
                }
            }
            AuthError::Infrastructure(format!("unable to create identity: {err}"))
        })?;

        Ok(map_identity(&row))
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        client
            .query_one(
                r#"
            INSERT INTO auth.sessions (
                session_id, subject_id, login, refresh_token_hash, issued_at,
                access_expires_at, refresh_expires_at, revoked_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (session_id) DO UPDATE SET
                subject_id = EXCLUDED.subject_id,
                login = EXCLUDED.login,
                refresh_token_hash = EXCLUDED.refresh_token_hash,
                issued_at = EXCLUDED.issued_at,
                access_expires_at = EXCLUDED.access_expires_at,
                refresh_expires_at = EXCLUDED.refresh_expires_at,
                revoked_at = EXCLUDED.revoked_at
            RETURNING session_id
            "#,
                &[
                    &session.session_id,
                    &session.subject_id,
                    &session.login,
                    &session.refresh_token_hash,
                    &session.issued_at,
                    &session.access_expires_at,
                    &session.refresh_expires_at,
                    &session.revoked_at,
                ],
            )
            .await
            .map_err(|err| AuthError::Infrastructure(format!("unable to save session: {err}")))?;
        Ok(())
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        let row = client
            .query_opt(
                r#"
            SELECT session_id, subject_id, login, refresh_token_hash, issued_at,
                   access_expires_at, refresh_expires_at, revoked_at
            FROM auth.sessions
            WHERE session_id = $1
            "#,
                &[&session_id],
            )
            .await
            .map_err(|err| AuthError::Infrastructure(format!("unable to load session: {err}")))?;
        Ok(row.as_ref().map(map_session))
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        client
            .execute(
                "UPDATE auth.sessions SET revoked_at = NOW() WHERE session_id = $1",
                &[&session_id],
            )
            .await
            .map_err(|err| AuthError::Infrastructure(format!("unable to revoke session: {err}")))?;
        Ok(())
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        client.execute(
            "UPDATE auth.sessions SET revoked_at = NOW() WHERE subject_id = $1 AND revoked_at IS NULL",
            &[&subject_id],
        ).await.map_err(|err| AuthError::Infrastructure(format!("unable to revoke subject sessions: {err}")))?;
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for PostgresLoginAttemptRepository {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        let client =
            self.pool.get().await.map_err(|err| {
                AuthError::Infrastructure(format!("unable to get connection: {err}"))
            })?;

        client.execute(
            "INSERT INTO auth.login_attempts (attempt_id, login, successful, attempted_at) VALUES ($1, $2, $3, $4)",
            &[&attempt.attempt_id, &attempt.login, &attempt.successful, &attempt.attempted_at],
        ).await.map_err(|err| AuthError::Infrastructure(format!("unable to record login attempt: {err}")))?;
        Ok(())
    }
}
