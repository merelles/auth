use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct RefreshTokenCommand {
    pub access_token: String,
    pub refresh_token: String,
}
