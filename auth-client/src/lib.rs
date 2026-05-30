mod error;
mod inprocess;

use async_trait::async_trait;
use auth_core::domain::{
    commands::{
        AuthenticateCommand, IntrospectTokenCommand, RefreshTokenCommand, RegisterIdentityCommand,
        RevokeTokenCommand,
    },
    entities::{AccessContext, AuthenticatedSession, Identity},
};

pub use error::AuthClientError;
pub use inprocess::AuthUseCaseClient;

#[async_trait]
pub trait AuthClient: Send + Sync {
    async fn register(&self, command: RegisterIdentityCommand)
        -> Result<Identity, AuthClientError>;
    async fn authenticate(
        &self,
        command: AuthenticateCommand,
    ) -> Result<AuthenticatedSession, AuthClientError>;
    async fn refresh(
        &self,
        command: RefreshTokenCommand,
    ) -> Result<AuthenticatedSession, AuthClientError>;
    async fn revoke(&self, command: RevokeTokenCommand) -> Result<(), AuthClientError>;
    async fn introspect(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<AccessContext, AuthClientError>;
}

#[cfg(test)]
mod tests {
    use super::{AuthClient, AuthUseCaseClient};
    use auth_core::domain::commands::{
        AuthenticateCommand, IntrospectTokenCommand, RefreshTokenCommand, RegisterIdentityCommand,
        RevokeTokenCommand,
    };
    use auth_password_argon2::{Argon2PasswordConfig, Argon2PasswordService};
    use auth_repo_memory::InMemoryIdentityRepository;
    use auth_token_jwt::{JwtTokenConfig, JwtTokenService};

    use auth_repo_memory::InMemoryLoginAttemptRepository;

    fn test_client() -> AuthUseCaseClient<
        InMemoryIdentityRepository,
        Argon2PasswordService,
        JwtTokenService<auth_repo_memory::InMemorySessionRepository>,
        InMemoryLoginAttemptRepository,
    > {
        let identities = InMemoryIdentityRepository::default();
        let passwords = Argon2PasswordService::new(
            Argon2PasswordConfig::recommended().with_pepper("test-pepper"),
        );
        let tokens = JwtTokenService::new(
            JwtTokenConfig {
                issuer: "auth-client-test".to_string(),
                secret: "jwt-secret-test".to_string(),
                access_ttl_seconds: 300,
                refresh_ttl_seconds: 3600,
            },
            auth_repo_memory::InMemorySessionRepository::default(),
        );

        AuthUseCaseClient::new(
            identities,
            passwords,
            tokens,
            InMemoryLoginAttemptRepository::default(),
        )
    }

    #[tokio::test]
    async fn inprocess_client_executes_full_auth_flow() {
        let client = test_client();

        let identity = client
            .register(RegisterIdentityCommand {
                login: "renato".to_string(),
                email: Some("renato@example.com".to_string()),
                password: "SenhaSegura123".to_string(),
            })
            .await
            .unwrap();

        let session = client
            .authenticate(AuthenticateCommand {
                login: identity.login.clone(),
                password: "SenhaSegura123".to_string(),
            })
            .await
            .unwrap();

        let context = client
            .introspect(IntrospectTokenCommand {
                access_token: session.access_token.clone(),
            })
            .await
            .unwrap();

        assert_eq!(context.subject_id, session.subject_id);
        assert_eq!(context.session_id, session.session_id);

        let refreshed = client
            .refresh(RefreshTokenCommand {
                access_token: session.access_token.clone(),
                refresh_token: session.refresh_token.clone(),
            })
            .await
            .unwrap();

        client
            .revoke(RevokeTokenCommand {
                access_token: refreshed.access_token,
            })
            .await
            .unwrap();
    }
}
