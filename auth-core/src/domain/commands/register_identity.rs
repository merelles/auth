use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct RegisterIdentityCommand {
    pub login: String,
    pub email: Option<String>,
    pub password: String,
}
