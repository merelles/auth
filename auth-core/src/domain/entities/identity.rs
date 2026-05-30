use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Identity {
    pub id: Uuid,
    pub login: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub active: bool,
}
