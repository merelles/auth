use crate::domain::{commands::RevokeTokenCommand, errors::AuthError, services::TokenService};

pub struct RevokeTokenUseCase<T> {
    tokens: T,
}

impl<T> RevokeTokenUseCase<T> {
    pub fn new(tokens: T) -> Self {
        Self { tokens }
    }
}

impl<T> RevokeTokenUseCase<T>
where
    T: TokenService,
{
    pub async fn execute(&self, command: RevokeTokenCommand) -> Result<(), AuthError> {
        self.tokens.revoke(&command.access_token).await
    }
}
