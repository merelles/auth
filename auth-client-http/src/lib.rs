use async_trait::async_trait;
use auth_client::{AuthClient, AuthClientError};
use auth_core::domain::{
    commands::{
        AuthenticateCommand, IntrospectTokenCommand, RefreshTokenCommand, RegisterIdentityCommand,
        RevokeTokenCommand,
    },
    entities::{AccessContext, AuthenticatedSession, Identity},
};

#[derive(Debug, Clone)]
pub struct AuthHttpClient {
    base_url: String,
    http: reqwest::Client,
}

impl AuthHttpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    async fn parse_response<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
    ) -> Result<T, AuthClientError> {
        if response.status().is_success() {
            response
                .json::<T>()
                .await
                .map_err(|err| AuthClientError::Client(err.to_string()))
        } else if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            Err(AuthClientError::InvalidToken)
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(AuthClientError::Client(body))
        }
    }
}

#[async_trait]
impl AuthClient for AuthHttpClient {
    async fn register(
        &self,
        command: RegisterIdentityCommand,
    ) -> Result<Identity, AuthClientError> {
        let response = self
            .http
            .post(format!("{}/auth/register", self.base_url))
            .json(&command)
            .send()
            .await
            .map_err(|err| AuthClientError::Client(err.to_string()))?;
        Self::parse_response(response).await
    }

    async fn authenticate(
        &self,
        command: AuthenticateCommand,
    ) -> Result<AuthenticatedSession, AuthClientError> {
        let response = self
            .http
            .post(format!("{}/auth/login", self.base_url))
            .json(&command)
            .send()
            .await
            .map_err(|err| AuthClientError::Client(err.to_string()))?;
        Self::parse_response(response).await
    }

    async fn refresh(
        &self,
        command: RefreshTokenCommand,
    ) -> Result<AuthenticatedSession, AuthClientError> {
        let response = self
            .http
            .post(format!("{}/auth/refresh", self.base_url))
            .json(&command)
            .send()
            .await
            .map_err(|err| AuthClientError::Client(err.to_string()))?;
        Self::parse_response(response).await
    }

    async fn revoke(&self, command: RevokeTokenCommand) -> Result<(), AuthClientError> {
        let response = self
            .http
            .post(format!("{}/auth/revoke", self.base_url))
            .json(&command)
            .send()
            .await
            .map_err(|err| AuthClientError::Client(err.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown error".to_string());
            Err(AuthClientError::Client(body))
        }
    }

    async fn introspect(
        &self,
        command: IntrospectTokenCommand,
    ) -> Result<AccessContext, AuthClientError> {
        let response = self
            .http
            .post(format!("{}/auth/introspect", self.base_url))
            .json(&command)
            .send()
            .await
            .map_err(|err| AuthClientError::Client(err.to_string()))?;
        Self::parse_response(response).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use actix_web::{
        post,
        web::{Data, Json},
        App, HttpResponse, HttpServer,
    };
    use auth_client::AuthClient;
    use auth_core::{
        application::use_cases::{
            AuthenticateUseCase, RefreshTokenUseCase, RegisterIdentityUseCase, RevokeTokenUseCase,
        },
        domain::{
            commands::{
                AuthenticateCommand, IntrospectTokenCommand, RefreshTokenCommand,
                RegisterIdentityCommand, RevokeTokenCommand,
            },
            errors::AuthError,
            services::TokenService,
        },
    };
    use auth_password_argon2::{Argon2PasswordConfig, Argon2PasswordService};
    use auth_repo_memory::{
        InMemoryIdentityRepository, InMemoryLoginAttemptRepository, InMemorySessionRepository,
    };
    use auth_token_jwt::{JwtTokenConfig, JwtTokenService};

    use super::AuthHttpClient;

    #[derive(Clone)]
    struct TestState {
        identities: InMemoryIdentityRepository,
        passwords: Argon2PasswordService,
        tokens: JwtTokenService<InMemorySessionRepository>,
        login_attempts: InMemoryLoginAttemptRepository,
    }

    fn map_error(error: AuthError) -> HttpResponse {
        match error {
            AuthError::InvalidCredentials | AuthError::InvalidToken => {
                HttpResponse::Unauthorized().body(error.to_string())
            }
            AuthError::IdentityAlreadyExists => HttpResponse::Conflict().body(error.to_string()),
            AuthError::InactiveIdentity => HttpResponse::Forbidden().body(error.to_string()),
            _ => HttpResponse::InternalServerError().body(error.to_string()),
        }
    }

    #[post("/auth/register")]
    async fn register(
        state: Data<TestState>,
        payload: Json<RegisterIdentityCommand>,
    ) -> HttpResponse {
        match RegisterIdentityUseCase::new(state.identities.clone(), state.passwords.clone())
            .execute(payload.into_inner())
            .await
        {
            Ok(identity) => HttpResponse::Created().json(identity),
            Err(error) => map_error(error),
        }
    }

    #[post("/auth/login")]
    async fn login(state: Data<TestState>, payload: Json<AuthenticateCommand>) -> HttpResponse {
        match AuthenticateUseCase::new(
            state.identities.clone(),
            state.passwords.clone(),
            state.tokens.clone(),
            state.login_attempts.clone(),
        )
        .execute(payload.into_inner())
        .await
        {
            Ok(session) => HttpResponse::Ok().json(session),
            Err(error) => map_error(error),
        }
    }

    #[post("/auth/refresh")]
    async fn refresh(state: Data<TestState>, payload: Json<RefreshTokenCommand>) -> HttpResponse {
        match RefreshTokenUseCase::new(state.tokens.clone())
            .execute(payload.into_inner())
            .await
        {
            Ok(session) => HttpResponse::Ok().json(session),
            Err(error) => map_error(error),
        }
    }

    #[post("/auth/revoke")]
    async fn revoke(state: Data<TestState>, payload: Json<RevokeTokenCommand>) -> HttpResponse {
        match RevokeTokenUseCase::new(state.tokens.clone())
            .execute(payload.into_inner())
            .await
        {
            Ok(()) => HttpResponse::NoContent().finish(),
            Err(error) => map_error(error),
        }
    }

    #[post("/auth/introspect")]
    async fn introspect(
        state: Data<TestState>,
        payload: Json<IntrospectTokenCommand>,
    ) -> HttpResponse {
        match state.tokens.introspect(&payload.access_token).await {
            Ok(context) => HttpResponse::Ok().json(context),
            Err(error) => map_error(error),
        }
    }

    async fn spawn_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let state = TestState {
            identities: InMemoryIdentityRepository::default(),
            passwords: Argon2PasswordService::new(
                Argon2PasswordConfig::recommended().with_pepper("http-test-pepper"),
            ),
            tokens: JwtTokenService::new(
                JwtTokenConfig {
                    issuer: "auth-http-test".to_string(),
                    secret: "jwt-secret-http-test".to_string(),
                    access_ttl_seconds: 300,
                    refresh_ttl_seconds: 3600,
                },
                InMemorySessionRepository::default(),
            ),
            login_attempts: InMemoryLoginAttemptRepository::default(),
        };

        let server = HttpServer::new(move || {
            App::new()
                .app_data(Data::new(state.clone()))
                .service(register)
                .service(login)
                .service(refresh)
                .service(revoke)
                .service(introspect)
        })
        .listen(listener)
        .unwrap()
        .run();

        tokio::spawn(server);
        address
    }

    #[tokio::test]
    async fn http_client_executes_full_auth_flow() {
        let base_url = spawn_server().await;
        let client = AuthHttpClient::new(base_url);

        let identity = client
            .register(RegisterIdentityCommand {
                login: "http-user".to_string(),
                email: Some("http-user@example.com".to_string()),
                password: "SenhaSegura456".to_string(),
            })
            .await
            .unwrap();
        let session = client
            .authenticate(AuthenticateCommand {
                login: identity.login,
                password: "SenhaSegura456".to_string(),
            })
            .await
            .unwrap();
        let context = client
            .introspect(IntrospectTokenCommand {
                access_token: session.access_token.clone(),
            })
            .await
            .unwrap();
        assert_eq!(context.session_id, session.session_id);
        let refreshed = client
            .refresh(RefreshTokenCommand {
                access_token: session.access_token,
                refresh_token: session.refresh_token,
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
