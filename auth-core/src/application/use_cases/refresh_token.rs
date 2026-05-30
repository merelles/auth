use crate::domain::{
    commands::RefreshTokenCommand, entities::AuthenticatedSession, errors::AuthError,
    services::TokenService,
};

pub struct RefreshTokenUseCase<T> {
    tokens: T,
}

impl<T> RefreshTokenUseCase<T> {
    pub fn new(tokens: T) -> Self {
        Self { tokens }
    }
}

impl<T> RefreshTokenUseCase<T>
where
    T: TokenService,
{
    pub async fn execute(
        &self,
        command: RefreshTokenCommand,
    ) -> Result<AuthenticatedSession, AuthError> {
        self.tokens
            .refresh(&command.access_token, &command.refresh_token)
            .await
    }
}
