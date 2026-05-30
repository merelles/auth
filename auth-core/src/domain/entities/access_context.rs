use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct AccessContext {
    pub subject_id: Uuid,
    pub login: String,
    pub session_id: Uuid,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
