mod config;

use actix_web::{
    get, post,
    web::{Data, Json},
    App, HttpResponse, HttpServer, Responder,
};
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
        entities::{AuthSession, Identity, LoginAttempt},
        errors::AuthError,
        repositories::{IdentityRepository, LoginAttemptRepository, SessionRepository},
        services::TokenService,
    },
};
use auth_password_argon2::{Argon2PasswordConfig, Argon2PasswordService};
use auth_repo_cache::{CachedLoginAttemptRepository, CachedSessionRepository};
use auth_repo_memory::{
    InMemoryIdentityRepository, InMemoryLoginAttemptRepository, InMemorySessionRepository,
};
use auth_repo_postgres::{
    PostgresAuthRepositories, PostgresIdentityRepository, PostgresLoginAttemptRepository,
    PostgresSessionRepository,
};
use auth_repo_redis::{RedisAuthRepositories, RedisLoginAttemptRepository, RedisSessionRepository};
use auth_token_jwt::{JwtTokenConfig, JwtTokenService};
use config::{AuthServiceConfig, StorageDialect};
use log;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Clone)]
struct AppState {
    identities: IdentityRepositoryAdapter,
    login_attempts: LoginAttemptRepositoryAdapter,
    passwords: Argon2PasswordService,
    tokens: JwtTokenService<SessionRepositoryAdapter>,
}

#[derive(Clone)]
enum IdentityRepositoryAdapter {
    Memory(InMemoryIdentityRepository),
    Postgres(PostgresIdentityRepository),
}

#[derive(Clone)]
enum SessionRepositoryAdapter {
    Memory(InMemorySessionRepository),
    Postgres(PostgresSessionRepository),
    Redis(RedisSessionRepository),
    Cached(CachedSessionRepository<RedisSessionRepository, PostgresSessionRepository>),
}

#[derive(Clone)]
enum LoginAttemptRepositoryAdapter {
    Memory(InMemoryLoginAttemptRepository),
    Postgres(PostgresLoginAttemptRepository),
    Redis(RedisLoginAttemptRepository),
    Cached(
        CachedLoginAttemptRepository<RedisLoginAttemptRepository, PostgresLoginAttemptRepository>,
    ),
}

#[async_trait]
impl IdentityRepository for IdentityRepositoryAdapter {
    async fn find_by_id(&self, identity_id: uuid::Uuid) -> Result<Option<Identity>, AuthError> {
        match self {
            Self::Memory(repository) => repository.find_by_id(identity_id).await,
            Self::Postgres(repository) => repository.find_by_id(identity_id).await,
        }
    }

    async fn find_by_login(&self, login_name: &str) -> Result<Option<Identity>, AuthError> {
        match self {
            Self::Memory(repository) => repository.find_by_login(login_name).await,
            Self::Postgres(repository) => repository.find_by_login(login_name).await,
        }
    }

    async fn create(&self, identity: Identity) -> Result<Identity, AuthError> {
        match self {
            Self::Memory(repository) => repository.create(identity).await,
            Self::Postgres(repository) => repository.create(identity).await,
        }
    }
}

#[async_trait]
impl SessionRepository for SessionRepositoryAdapter {
    async fn save(&self, session: AuthSession) -> Result<(), AuthError> {
        match self {
            Self::Memory(repository) => repository.save(session).await,
            Self::Postgres(repository) => repository.save(session).await,
            Self::Redis(repository) => repository.save(session).await,
            Self::Cached(repository) => repository.save(session).await,
        }
    }

    async fn find_by_session_id(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<Option<AuthSession>, AuthError> {
        match self {
            Self::Memory(repository) => repository.find_by_session_id(session_id).await,
            Self::Postgres(repository) => repository.find_by_session_id(session_id).await,
            Self::Redis(repository) => repository.find_by_session_id(session_id).await,
            Self::Cached(repository) => repository.find_by_session_id(session_id).await,
        }
    }

    async fn revoke_by_session_id(&self, session_id: uuid::Uuid) -> Result<(), AuthError> {
        match self {
            Self::Memory(repository) => repository.revoke_by_session_id(session_id).await,
            Self::Postgres(repository) => repository.revoke_by_session_id(session_id).await,
            Self::Redis(repository) => repository.revoke_by_session_id(session_id).await,
            Self::Cached(repository) => repository.revoke_by_session_id(session_id).await,
        }
    }

    async fn revoke_by_subject_id(&self, subject_id: uuid::Uuid) -> Result<(), AuthError> {
        match self {
            Self::Memory(repository) => repository.revoke_by_subject_id(subject_id).await,
            Self::Postgres(repository) => repository.revoke_by_subject_id(subject_id).await,
            Self::Redis(repository) => repository.revoke_by_subject_id(subject_id).await,
            Self::Cached(repository) => repository.revoke_by_subject_id(subject_id).await,
        }
    }
}

#[async_trait]
impl LoginAttemptRepository for LoginAttemptRepositoryAdapter {
    async fn record(&self, attempt: LoginAttempt) -> Result<(), AuthError> {
        match self {
            Self::Memory(repository) => repository.record(attempt).await,
            Self::Postgres(repository) => repository.record(attempt).await,
            Self::Redis(repository) => repository.record(attempt).await,
            Self::Cached(repository) => repository.record(attempt).await,
        }
    }
}

fn map_error(error: AuthError) -> HttpResponse {
    match error {
        AuthError::InvalidCredentials | AuthError::InvalidToken | AuthError::SessionNotFound => {
            HttpResponse::Unauthorized().body(error.to_string())
        }
        AuthError::IdentityAlreadyExists => HttpResponse::Conflict().body(error.to_string()),
        AuthError::InactiveIdentity => HttpResponse::Forbidden().body(error.to_string()),
        _ => HttpResponse::InternalServerError().body(error.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses((status = 200, description = "Public liveness endpoint"))
)]
#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().body("ok")
}

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "Auth",
    request_body = auth_core::domain::commands::RegisterIdentityCommand,
    responses(
        (status = 201, description = "Public registration endpoint", body = auth_core::domain::entities::Identity),
        (status = 409, description = "Identity already exists")
    )
)]
#[post("/auth/register")]
async fn register(state: Data<AppState>, payload: Json<RegisterIdentityCommand>) -> impl Responder {
    match RegisterIdentityUseCase::new(state.identities.clone(), state.passwords.clone())
        .execute(payload.into_inner())
        .await
    {
        Ok(identity) => {
            log::info!("Registro bem-sucedido");
            HttpResponse::Created().json(identity)
        }
        Err(error) => {
            log::error!("Registro falhou: {error}");
            map_error(error)
        }
    }
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "Auth",
    request_body = auth_core::domain::commands::AuthenticateCommand,
    responses(
        (status = 200, description = "Public login endpoint", body = auth_core::domain::entities::AuthenticatedSession),
        (status = 401, description = "Invalid credentials")
    )
)]
#[post("/auth/login")]
async fn login(state: Data<AppState>, payload: Json<AuthenticateCommand>) -> impl Responder {
    log::info!("Iniciando autenticação {:?}", &payload);
    match AuthenticateUseCase::new(
        state.identities.clone(),
        state.passwords.clone(),
        state.tokens.clone(),
        state.login_attempts.clone(),
    )
    .execute(payload.into_inner())
    .await
    {
        Ok(session) => {
            log::info!("Autenticação bem-sucedida");
            HttpResponse::Ok().json(session)
        }
        Err(error) => {
            log::error!("Autenticação falhou: {error}");
            map_error(error)
        }
    }
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Auth",
    request_body = auth_core::domain::commands::RefreshTokenCommand,
    responses(
        (status = 200, description = "Public token refresh endpoint", body = auth_core::domain::entities::AuthenticatedSession),
        (status = 401, description = "Invalid token")
    )
)]
#[post("/auth/refresh")]
async fn refresh(state: Data<AppState>, payload: Json<RefreshTokenCommand>) -> impl Responder {
    match RefreshTokenUseCase::new(state.tokens.clone())
        .execute(payload.into_inner())
        .await
    {
        Ok(session) => {
            log::info!("Refresh bem-sucedido");
            HttpResponse::Ok().json(session)
        }
        Err(error) => {
            log::error!("Refresh falhou: {error}");
            map_error(error)
        }
    }
}

#[utoipa::path(
    post,
    path = "/auth/revoke",
    tag = "Auth",
    request_body = auth_core::domain::commands::RevokeTokenCommand,
    responses(
        (status = 204, description = "Public token revoke endpoint"),
        (status = 401, description = "Invalid token")
    )
)]
#[post("/auth/revoke")]
async fn revoke(state: Data<AppState>, payload: Json<RevokeTokenCommand>) -> impl Responder {
    match RevokeTokenUseCase::new(state.tokens.clone())
        .execute(payload.into_inner())
        .await
    {
        Ok(()) => {
            log::info!("Revoke bem-sucedido");
            HttpResponse::NoContent().finish()
        }
        Err(error) => {
            log::error!("Revoke falhou: {error}");
            map_error(error)
        }
    }
}

#[utoipa::path(
    post,
    path = "/auth/introspect",
    tag = "Auth",
    request_body = auth_core::domain::commands::IntrospectTokenCommand,
    responses(
        (status = 200, description = "Service-to-service token introspection endpoint", body = auth_core::domain::entities::AccessContext),
        (status = 401, description = "Invalid token")
    )
)]
#[post("/auth/introspect")]
async fn introspect(
    state: Data<AppState>,
    payload: Json<IntrospectTokenCommand>,
) -> impl Responder {
    match state.tokens.introspect(&payload.access_token).await {
        Ok(context) => {
            log::info!("Introspect bem-sucedido");
            HttpResponse::Ok().json(context)
        }
        Err(error) => {
            log::error!("Introspect falhou: {error}");
            map_error(error)
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(health, register, login, refresh, revoke, introspect),
    components(
        schemas(
            auth_core::domain::commands::RegisterIdentityCommand,
            auth_core::domain::commands::AuthenticateCommand,
            auth_core::domain::commands::RefreshTokenCommand,
            auth_core::domain::commands::RevokeTokenCommand,
            auth_core::domain::commands::IntrospectTokenCommand,
            auth_core::domain::entities::Identity,
            auth_core::domain::entities::AuthenticatedSession,
            auth_core::domain::entities::AccessContext
        )
    ),
    tags(
        (name = "Health", description = "Public service health endpoints"),
        (name = "Auth", description = "Authentication endpoints. Current contract does not require bearer auth in Swagger.")
    )
)]
struct ApiDoc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let config = AuthServiceConfig::from_env();

    let host = std::env::var("AUTH_API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("AUTH_API_PORT").unwrap_or_else(|_| "9090".to_string());
    let bind_address = format!("{host}:{port}");

    println!("AUTH Service starting...");
    println!("Health: http://{bind_address}/health");
    println!("Swagger: http://{bind_address}/swagger-ui/");
    println!("Protected POST: http://{bind_address}/auth/introspect");
    println!("Protected POST: http://{bind_address}/auth/login");
    println!("Protected POST: http://{bind_address}/auth/refresh");
    println!("Protected POST: http://{bind_address}/auth/register");
    println!("Protected POST: http://{bind_address}/auth/revoke");

    let redis =
        RedisAuthRepositories::from_env().map_err(|err| std::io::Error::other(err.to_string()))?;
    let postgres = PostgresAuthRepositories::from_env()
        .await
        .map_err(|err| std::io::Error::other(err.to_string()))?;

    let (identities, session_repository, login_attempts) = match config.storage_dialect {
        StorageDialect::Memory => (
            IdentityRepositoryAdapter::Memory(InMemoryIdentityRepository::default()),
            SessionRepositoryAdapter::Memory(InMemorySessionRepository::default()),
            LoginAttemptRepositoryAdapter::Memory(InMemoryLoginAttemptRepository::default()),
        ),
        StorageDialect::Postgres => {
            let postgres = postgres
                .ok_or_else(|| std::io::Error::other("AUTH_STORAGE_DIALECT=postgres requires AUTH_DATABASE_*"))?;

            postgres
                .ensure_schema()
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?;

            (
                IdentityRepositoryAdapter::Postgres(postgres.identities()),
                SessionRepositoryAdapter::Postgres(postgres.sessions()),
                LoginAttemptRepositoryAdapter::Postgres(postgres.login_attempts()),
            )
        }
        StorageDialect::Redis => {
            let redis = redis
                .ok_or_else(|| std::io::Error::other("AUTH_STORAGE_DIALECT=redis requires REDIS_URL"))?;

            (
                IdentityRepositoryAdapter::Memory(InMemoryIdentityRepository::default()),
                SessionRepositoryAdapter::Redis(redis.sessions()),
                LoginAttemptRepositoryAdapter::Redis(redis.login_attempts()),
            )
        }
        StorageDialect::PostgresRedisCache => {
            let postgres = postgres.ok_or_else(|| {
                std::io::Error::other(
                    "AUTH_STORAGE_DIALECT=postgres_redis_cache requires AUTH_DATABASE_*",
                )
            })?;
            let redis = redis.ok_or_else(|| {
                std::io::Error::other("AUTH_STORAGE_DIALECT=postgres_redis_cache requires REDIS_URL")
            })?;

            postgres
                .ensure_schema()
                .await
                .map_err(|err| std::io::Error::other(err.to_string()))?;

            (
                IdentityRepositoryAdapter::Postgres(postgres.identities()),
                SessionRepositoryAdapter::Cached(CachedSessionRepository::new(
                    redis.sessions(),
                    postgres.sessions(),
                )),
                LoginAttemptRepositoryAdapter::Cached(CachedLoginAttemptRepository::new(
                    redis.login_attempts(),
                    postgres.login_attempts(),
                )),
            )
        }
        StorageDialect::MongoDb => {
            return Err(std::io::Error::other(
                "AUTH_STORAGE_DIALECT=mongodb is not implemented yet",
            ));
        }
    };

    let state = AppState {
        identities,
        login_attempts,
        passwords: Argon2PasswordService::new(Argon2PasswordConfig::from_env()),
        tokens: JwtTokenService::new(JwtTokenConfig::from_env(), session_repository),
    };

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
            .service(health)
            .service(register)
            .service(login)
            .service(refresh)
            .service(revoke)
            .service(introspect)
    })
    .bind((config.host, config.port))?
    .run()
    .await
}
