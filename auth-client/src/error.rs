use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthClientError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid token")]
    InvalidToken,
    #[error("identity already exists")]
    IdentityAlreadyExists,
    #[error("client error: {0}")]
    Client(String),
}
