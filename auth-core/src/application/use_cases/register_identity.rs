use uuid::Uuid;

use crate::domain::{
    commands::RegisterIdentityCommand, entities::Identity, errors::AuthError,
    repositories::IdentityRepository, services::PasswordService,
};

pub struct RegisterIdentityUseCase<I, P> {
    identities: I,
    passwords: P,
}

impl<I, P> RegisterIdentityUseCase<I, P> {
    pub fn new(identities: I, passwords: P) -> Self {
        Self {
            identities,
            passwords,
        }
    }
}

impl<I, P> RegisterIdentityUseCase<I, P>
where
    I: IdentityRepository,
    P: PasswordService,
{
    pub async fn execute(&self, command: RegisterIdentityCommand) -> Result<Identity, AuthError> {
        if self
            .identities
            .find_by_login(&command.login)
            .await?
            .is_some()
        {
            return Err(AuthError::IdentityAlreadyExists);
        }

        let password_hash = self.passwords.hash(&command.password).await?;

        let identity = Identity {
            id: Uuid::new_v4(),
            login: command.login,
            email: command.email,
            password_hash,
            active: true,
        };

        self.identities.create(identity).await
    }
}
