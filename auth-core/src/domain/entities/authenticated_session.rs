use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct AuthenticatedSession {
    pub session_id: Uuid,
    pub subject_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_at: DateTime<Utc>,
}
