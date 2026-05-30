use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct AuthSession {
    pub session_id: Uuid,
    pub subject_id: Uuid,
    pub login: String,
    pub refresh_token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}
