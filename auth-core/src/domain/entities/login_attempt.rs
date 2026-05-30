use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct LoginAttempt {
    pub attempt_id: Uuid,
    pub login: String,
    pub successful: bool,
    pub attempted_at: DateTime<Utc>,
}
