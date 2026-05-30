use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("identity is inactive")]
    InactiveIdentity,
    #[error("identity already exists")]
    IdentityAlreadyExists,
    #[error("session not found")]
    SessionNotFound,
    #[error("token is invalid")]
    InvalidToken,
    #[error("token is expired")]
    ExpiredToken,
    #[error("identity not found")]
    IdentityNotFound,
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("infrastructure error: {0}")]
    Infrastructure(String),
}
