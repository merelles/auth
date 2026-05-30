mod config;

use async_trait::async_trait;
use auth_core::domain::{
    entities::{AuthSession, Identity, LoginAttempt},
    errors::AuthError,
    repositories::{IdentityRepository, LoginAttemptRepository, SessionRepository},
};
use chrono::Utc;
use mongodb::{
    bson::{doc, Bson, Document},
    options::IndexOptions,
    Client, Collection, IndexModel,
};
use uuid::Uuid;

pub use config::MongoConfig;

#[derive(Clone)]
pub struct MongoIdentityRepository {
    collection: Collection<Document>,
}

#[derive(Clone)]
pub struct MongoSessionRepository {
    collection: Collection<Document>,
}

#[derive(Clone)]
pub struct MongoLoginAttemptRepository {
    collection: Collection<Document>,
}

#[derive(Clone)]
pub struct MongoAuthRepositories {
    identities: Collection<Document>,
    sessions: Collection<Document>,
    login_attempts: Collection<Document>,
}

impl MongoAuthRepositories {
    pub async fn connect(uri: &str, database: &str) -> Result<Self, AuthError> {
        let client = Client::with_uri_str(uri).await.map_err(|err| {
            AuthError::Infrastructure(format!("unable to connect to mongodb: {err}"))
        })?;
        let db = client.database(database);

        Ok(Self {
            identities: db.collection("identities"),
            sessions: db.collection("sessions"),
            login_attempts: db.collection("login_attempts"),
        })
    }

    pub async fn from_env() -> Result<Option<Self>, AuthError> {
        match MongoConfig::from_env() {
            Some(config) => Self::connect(&config.uri, &config.database).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn ensure_indexes(&self) -> Result<(), AuthError> {
        self.identities
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("idx_identities_id".to_string()))
                            .unique(Some(true))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to create identities id index: {err}"))
            })?;

        self.identities
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "login": 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("idx_identities_login".to_string()))
                            .unique(Some(true))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!(
                    "unable to create identities login index: {err}"
                ))
            })?;

        self.sessions
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "session_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("idx_sessions_session_id".to_string()))
                            .unique(Some(true))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!(
                    "unable to create sessions session_id index: {err}"
                ))
            })?;

        self.sessions
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "subject_id": 1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("idx_sessions_subject_id".to_string()))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!(
                    "unable to create sessions subject_id index: {err}"
                ))
            })?;

        self.login_attempts
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "login": 1, "attempted_at": -1 })
                    .options(
                        IndexOptions::builder()
                            .name(Some("idx_login_attempts_login_attempted_at".to_string()))
                            .build(),
                    )
                    .build(),
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!(
                    "unable to create login attempts index: {err}"
                ))
            })?;

        Ok(())
    }

    pub fn identities(&self) -> MongoIdentityRepository {
        MongoIdentityRepository {
            collection: self.identities.clone(),
        }
    }

    pub fn sessions(&self) -> MongoSessionRepository {
        MongoSessionRepository {
            collection: self.sessions.clone(),
        }
    }

    pub fn login_attempts(&self) -> MongoLoginAttemptRepository {
        MongoLoginAttemptRepository {
            collection: self.login_attempts.clone(),
        }
    }
}

fn identity_to_doc(identity: &Identity) -> Document {
    doc! {
        "id": identity.id.to_string(),
        "login": identity.login.clone(),
        "email": identity.email.clone(),
        "password_hash": identity.password_hash.clone(),
        "active": identity.active,
    }
}

fn identity_from_doc(doc: Document) -> Result<Identity, AuthError> {
    let id = doc
        .get_str("id")
        .map_err(|err| AuthError::Infrastructure(format!("identity missing id: {err}")))?;
    let login = doc
        .get_str("login")
        .map_err(|err| AuthError::Infrastructure(format!("identity missing login: {err}")))?;
    let password_hash = doc.get_str("password_hash").map_err(|err| {
        AuthError::Infrastructure(format!("identity missing password_hash: {err}"))
    })?;
    let active = doc
        .get_bool("active")
        .map_err(|err| AuthError::Infrastructure(format!("identity missing active: {err}")))?;
    let email = match doc.get("email") {
        Some(Bson::String(value)) => Some(value.clone()),
        _ => None,
    };

    Ok(Identity {
        id: Uuid::parse_str(id)
            .map_err(|err| AuthError::Infrastructure(format!("invalid identity id: {err}")))?,
        login: login.to_string(),
        email,
        password_hash: password_hash.to_string(),
        active,
    })
}

fn session_to_doc(session: &AuthSession) -> Document {
    doc! {
        "session_id": session.session_id.to_string(),
        "subject_id": session.subject_id.to_string(),
        "login": session.login.clone(),
        "refresh_token_hash": session.refresh_token_hash.clone(),
        "issued_at": session.issued_at.to_rfc3339(),
        "access_expires_at": session.access_expires_at.to_rfc3339(),
        "refresh_expires_at": session.refresh_expires_at.to_rfc3339(),
        "revoked_at": session.revoked_at.map(|value| value.to_rfc3339()),
    }
}

fn session_from_doc(doc: Document) -> Result<AuthSession, AuthError> {
    let session_id = doc
        .get_str("session_id")
        .map_err(|err| AuthError::Infrastructure(format!("session missing session_id: {err}")))?;
    let subject_id = doc
        .get_str("subject_id")
        .map_err(|err| AuthError::Infrastructure(format!("session missing subject_id: {err}")))?;
    let login = doc
        .get_str("login")
        .map_err(|err| AuthError::Infrastructure(format!("session missing login: {err}")))?;
    let refresh_token_hash = doc.get_str("refresh_token_hash").map_err(|err| {
        AuthError::Infrastructure(format!("session missing refresh_token_hash: {err}"))
    })?;
    let issued_at = doc
        .get_str("issued_at")
        .map_err(|err| AuthError::Infrastructure(format!("session missing issued_at: {err}")))?;
    let access_expires_at = doc.get_str("access_expires_at").map_err(|err| {
        AuthError::Infrastructure(format!("session missing access_expires_at: {err}"))
    })?;
    let refresh_expires_at = doc.get_str("refresh_expires_at").map_err(|err| {
        AuthError::Infrastructure(format!("session missing refresh_expires_at: {err}"))
    })?;

    let revoked_at = match doc.get("revoked_at") {
        Some(Bson::String(value)) => Some(
            chrono::DateTime::parse_from_rfc3339(value)
                .map_err(|err| {
                    AuthError::Infrastructure(format!("invalid session revoked_at: {err}"))
                })?
                .with_timezone(&Utc),
        ),
        _ => None,
    };

    Ok(AuthSession {
        session_id: Uuid::parse_str(session_id)
            .map_err(|err| AuthError::Infrastructure(format!("invalid session id: {err}")))?,
        subject_id: Uuid::parse_str(subject_id)
            .map_err(|err| AuthError::Infrastructure(format!("invalid subject id: {err}")))?,
        login: login.to_string(),
        refresh_token_hash: refresh_token_hash.to_string(),
        issued_at: chrono::DateTime::parse_from_rfc3339(issued_at)
            .map_err(|err| AuthError::Infrastructure(format!("invalid issued_at: {err}")))?
            .with_timezone(&Utc),
        access_expires_at: chrono::DateTime::parse_from_rfc3339(access_expires_at)
            .map_err(|err| AuthError::Infrastructure(format!("invalid access_expires_at: {err}")))?
            .with_timezone(&Utc),
        refresh_expires_at: chrono::DateTime::parse_from_rfc3339(refresh_expires_at)
            .map_err(|err| AuthError::Infrastructure(format!("invalid refresh_expires_at: {err}")))?
            .with_timezone(&Utc),
        revoked_at,
    })
}

fn login_attempt_to_doc(attempt: &LoginAttempt) -> Document {
    doc! {
        "attempt_id": attempt.attempt_id.to_string(),
        "login": attempt.login.clone(),
        "successful": attempt.successful,
        "attempted_at": attempt.attempted_at.to_rfc3339(),
    }
}

#[async_trait]
impl IdentityRepository for MongoIdentityRepository {
    async fn find_by_id(&self, identity_id: Uuid) -> Result<Option<Identity>, AuthError> {
        let doc = self
            .collection
            .find_one(doc! { "id": identity_id.to_string() })
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to find identity by id: {err}"))
            })?;

        match doc {
            Some(value) => identity_from_doc(value).map(Some),
            None => Ok(None),
        }
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<Identity>, AuthError> {
        let doc = self
            .collection
            .find_one(doc! { "login": login })
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to find identity by login: {err}"))
            })?;

        match doc {
            Some(value) => identity_from_doc(value).map(Some),
            None => Ok(None),
        }
    }

    async fn create(&self, identity: Identity) -> Result<Identity, AuthError> {
        let result = self
            .collection
            .insert_one(identity_to_doc(&identity))
            .await;

        match result {
            Ok(_) => Ok(identity),
            Err(err) if err.to_string().contains("E11000") => Err(AuthError::IdentityAlreadyExists),
            Err(err) => Err(AuthError::Infrastructure(format!(
                "unable to create identity: {err}"
            ))),
        }
    }
}

#[async_trait]
impl SessionRepository for MongoSessionRepository {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        self.collection
            .update_one(
                doc! { "session_id": session.session_id.to_string() },
                doc! { "$set": session_to_doc(&session) },
            )
            .upsert(true)
            .await
            .map_err(|err| AuthError::Infrastructure(format!("unable to save session: {err}")))?;
        Ok(())
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError> {
        let doc = self
            .collection
            .find_one(doc! { "session_id": session_id.to_string() })
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to find session by id: {err}"))
            })?;

        match doc {
            Some(value) => session_from_doc(value).map(Some),
            None => Ok(None),
        }
    }

    async fn revoke_by_session_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        self.collection
            .update_one(
                doc! { "session_id": session_id.to_string() },
                doc! { "$set": { "revoked_at": Utc::now().to_rfc3339() } },
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to revoke session by id: {err}"))
            })?;
        Ok(())
    }

    async fn revoke_by_subject_id(&self, subject_id: Uuid) -> Result<(), AuthError> {
        self.collection
            .update_many(
                doc! { "subject_id": subject_id.to_string() },
                doc! { "$set": { "revoked_at": Utc::now().to_rfc3339() } },
            )
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to revoke sessions by subject: {err}"))
            })?;
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for MongoLoginAttemptRepository {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        self.collection
            .insert_one(login_attempt_to_doc(&attempt))
            .await
            .map_err(|err| {
                AuthError::Infrastructure(format!("unable to record login attempt: {err}"))
            })?;
        Ok(())
    }
}
