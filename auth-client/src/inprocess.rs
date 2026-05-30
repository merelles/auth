use async_trait::async_trait;
use auth_core::{
    application::use_cases::{
        AuthenticateUseCase, RefreshTokenUseCase, RegisterIdentityUseCase, RevokeTokenUseCase,
    },
    domain::{
        commands::{
            AuthenticateCommand, IntrospectTokenCommand, RefreshTokenCommand,
            RegisterIdentityCommand, RevokeTokenCommand,
        },
        entities::{AccessContext, AuthenticatedSession, Identity},
        errors::AuthError,
        repositories::{IdentityRepository, LoginAttemptRepository},
        services::{PasswordService, TokenService},
    },
};

use crate::{AuthClient, AuthClientError};

#[derive(Debug, Clone)]
pub struct AuthUseCaseClient<I, P, T, L> {
    identities: I,
    passwords: P,
    tokens: T,
    login_attempts: L,
}

impl<I, P, T, L> AuthUseCaseClient<I, P, T, L> {
    pub fn new(identities: I, passwords: P, tokens: T, login_attempts: L) -> Self {
        Self {
            identities,
            passwords,
            tokens,
            login_attempts,
        }
    }
}

fn map_error(error: AuthError) -> AuthClientError {
    match error {
        AuthError::InvalidCredentials => AuthClientError::InvalidCredentials,
        AuthError::InvalidToken | AuthError::ExpiredToken | AuthError::SessionNotFound => {
            AuthClientError::InvalidToken
        }
        AuthError::IdentityAlreadyExists => AuthClientError::IdentityAlreadyExists,
        other => AuthClientError::Client(other.to_string()),
    }
}

#[async_trait]
impl<I, P, T, L> AuthClient for AuthUseCaseClient<I, P, T, L>
where
    I: IdentityRepository + Clone,
    P: PasswordService + Clone,
    T: TokenService + Clone,
    L: LoginAttemptRepository + Clone,
{
    async fn register(
        &self,
        command: RegisterIdentityCommand,
    ) -> Result<Identity, AuthClientError> {
        RegisterIdentityUseCase::new(self.identities.clone(), self.passwords.clone())
            .execute(command)
            .await
            .map_err(map_error)
    }

    async fn authenticate(
        &self,
        command: AuthenticateCommand,
    ) -> Result<AuthenticatedSession, AuthClientError> {
        AuthenticateUseCase::new(
            self.identities.clone(),
            self.passwords.clone(),
            self.tokens.clone(),
            self.login_attempts.clone(),
        )
        .execute(command)
        .await
        .map_err(map_error)
    }

    async fn refresh(
        &self,
        command: RefreshTokenCommand,
    ) -> Result<AuthenticatedSession, AuthClientError> {
        RefreshTokenUseCase::new(self.tokens.clone())
            .execute(command)
            .await
            .map_err(map_error)
    }

    async fn revoke(&self, command: RevokeTokenCommand) -> Result<(), AuthClientError> {
        RevokeTokenUseCase::new(self.tokens.clone())
            .execute(command)
            .await
            .map_err(map_error)
    }

    async fn introspect(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<AccessContext, AuthClientError> {
        self.tokens
            .introspect(&command.access_token)
            .await
            .map_err(map_error)
    }
}
