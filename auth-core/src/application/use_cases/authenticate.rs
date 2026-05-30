use chrono::Utc;
use uuid::Uuid;

use crate::domain::{
    commands::AuthenticateCommand,
    entities::{AuthenticatedSession, LoginAttempt},
    errors::AuthError,
    repositories::{IdentityRepository, LoginAttemptRepository},
    services::{PasswordService, TokenService},
};

pub struct AuthenticateUseCase<I, P, T, L> {
    identities: I,
    passwords: P,
    tokens: T,
    login_attempts: L,
}

impl<I, P, T, L> AuthenticateUseCase<I, P, T, L> {
    pub fn new(identities: I, passwords: P, tokens: T, login_attempts: L) -> Self {
        Self {
            identities,
            passwords,
            tokens,
            login_attempts,
        }
    }
}

impl<I, P, T, L> AuthenticateUseCase<I, P, T, L>
where
    I: IdentityRepository,
    P: PasswordService,
    T: TokenService,
    L: LoginAttemptRepository,
{
    pub async fn execute(
        &self,
        command: AuthenticateCommand,
    ) -> Result<AuthenticatedSession, AuthError> {
        let identity = self
            .identities
            .find_by_login(&command.login)
            .await?
            .ok_or_else(|| AuthError::InvalidCredentials);

        let identity = match identity {
            Ok(identity) => identity,
            Err(err) => {
                self.login_attempts
                    .record(LoginAttempt {
                        attempt_id: Uuid::new_v4(),
                        login: command.login.clone(),
                        successful: false,
                        attempted_at: Utc::now(),
                    })
                    .await?;
                return Err(err);
            }
        };

        if !identity.active {
            self.login_attempts
                .record(LoginAttempt {
                    attempt_id: Uuid::new_v4(),
                    login: command.login.clone(),
                    successful: false,
                    attempted_at: Utc::now(),
                })
                .await?;
            return Err(AuthError::InactiveIdentity);
        }

        let verified = self
            .passwords
            .verify(&command.password, &identity.password_hash)
            .await?;

        if !verified {
            self.login_attempts
                .record(LoginAttempt {
                    attempt_id: Uuid::new_v4(),
                    login: command.login.clone(),
                    successful: false,
                    attempted_at: Utc::now(),
                })
                .await?;
            return Err(AuthError::InvalidCredentials);
        }

        self.login_attempts
            .record(LoginAttempt {
                attempt_id: Uuid::new_v4(),
                login: command.login,
                successful: true,
                attempted_at: Utc::now(),
            })
            .await?;

        self.tokens.issue_for(identity).await
    }
}
