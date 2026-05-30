use crate::domain::{
    entities::{AuthenticatedSession, Identity},
    errors::AuthError,
    services::TokenService,
};

pub struct IssueTokenUseCase<T> {
    tokens: T,
}

impl<T> IssueTokenUseCase<T> {
    pub fn new(tokens: T) -> Self {
        Self { tokens }
    }
}

impl<T> IssueTokenUseCase<T>
where
    T: TokenService,
{
    pub async fn execute(&self, identity: Identity) -> Result<AuthenticatedSession, AuthError> {
        self.tokens.issue_for(identity).await
    }
}
