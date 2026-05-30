use async_trait::async_trait;
use auth_core::domain::{
    entities::{AccessContext, AuthSession, AuthenticatedSession, Identity},
    errors::AuthError,
    repositories::SessionRepository,
    services::TokenService,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

mod config;
pub use config::JwtTokenConfig;

#[derive(Debug, Clone)]
pub struct JwtTokenService<S> {
    config: JwtTokenConfig,
    sessions: S,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenClaims {
    sub: Uuid,
    login: String,
    session_id: Uuid,
    token_kind: String,
    iss: String,
    iat: i64,
    exp: i64,
}

impl<S> JwtTokenService<S> {
    pub fn new(config: JwtTokenConfig, sessions: S) -> Self {
        Self { config, sessions }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_secret(self.config.secret.as_bytes())
    }

    fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_secret(self.config.secret.as_bytes())
    }

    fn validation(&self) -> Validation {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        validation.validate_exp = true;
        validation
    }

    fn encode_token(
        &self,
        identity: &Identity,
        session_id: Uuid,
        token_kind: &str,
        ttl_seconds: i64,
    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let claims = TokenClaims {
            sub: identity.id,
            login: identity.login.clone(),
            session_id,
            token_kind: token_kind.to_string(),
            iss: self.config.issuer.clone(),
            iat: now.timestamp(),
            exp: (now + Duration::seconds(ttl_seconds)).timestamp(),
        };

        encode(&Header::default(), &claims, &self.encoding_key())
            .map_err(|err| AuthError::Infrastructure(format!("unable to encode token: {err}")))
    }

    fn decode_token(&self, token: &str, expected_kind: &str) -> Result<TokenClaims, AuthError> {
        let token_data = decode::<TokenClaims>(token, &self.decoding_key(), &self.validation())
            .map_err(|_| AuthError::InvalidToken)?;
        if token_data.claims.token_kind != expected_kind {
            return Err(AuthError::InvalidToken);
        }
        Ok(token_data.claims)
    }

    fn hash_refresh_token(refresh_token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(refresh_token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl<S> JwtTokenService<S>
where
    S: SessionRepository,
{
    async fn build_and_store_session(
        &self,
        identity: &Identity,
        session_id: Uuid,
    ) -> Result<AuthenticatedSession, AuthError> {
        let issued_at = Utc::now();
        let access_expires_at = issued_at + Duration::seconds(self.config.access_ttl_seconds);
        let refresh_expires_at = issued_at + Duration::seconds(self.config.refresh_ttl_seconds);
        let access_token = self.encode_token(
            identity,
            session_id,
            "access",
            self.config.access_ttl_seconds,
        )?;
        let refresh_token = self.encode_token(
            identity,
            session_id,
            "refresh",
            self.config.refresh_ttl_seconds,
        )?;

        self.sessions
            .save(AuthSession {
                session_id,
                subject_id: identity.id,
                login: identity.login.clone(),
                refresh_token_hash: Self::hash_refresh_token(&refresh_token),
                issued_at,
                access_expires_at,
                refresh_expires_at,
                revoked_at: None,
            })
            .await?;

        Ok(AuthenticatedSession {
            session_id,
            subject_id: identity.id,
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_at: access_expires_at,
        })
    }
}

#[async_trait]
impl<S> TokenService for JwtTokenService<S>
where
    S: SessionRepository + Send + Sync + Clone,
{
    async fn issue_for(&self, identity: Identity) -> Result<AuthenticatedSession, AuthError> {
        self.build_and_store_session(&identity, Uuid::new_v4())
            .await
    }

    async fn refresh(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<AuthenticatedSession, AuthError> {
        let access_claims = self.decode_token(access_token, "access")?;
        let refresh_claims = self.decode_token(refresh_token, "refresh")?;

        if access_claims.session_id != refresh_claims.session_id
            || access_claims.sub != refresh_claims.sub
        {
            return Err(AuthError::InvalidToken);
        }

        let stored_session = self
            .sessions
            .find_by_session_id(refresh_claims.session_id)
            .await?
            .ok_or(AuthError::SessionNotFound)?;

        if stored_session.revoked_at.is_some()
            || stored_session.subject_id != refresh_claims.sub
            || stored_session.refresh_token_hash != Self::hash_refresh_token(refresh_token)
            || stored_session.refresh_expires_at < Utc::now()
        {
            return Err(AuthError::InvalidToken);
        }

        let identity = Identity {
            id: refresh_claims.sub,
            login: refresh_claims.login,
            email: None,
            password_hash: String::new(),
            active: true,
        };

        self.build_and_store_session(&identity, refresh_claims.session_id)
            .await
    }

    async fn revoke(&self, access_token: &str) -> Result<(), AuthError> {
        let claims = self.decode_token(access_token, "access")?;
        self.sessions.revoke_by_session_id(claims.session_id).await
    }

    async fn introspect(&self, access_token: &str) -> Result<AccessContext, AuthError> {
        let claims = self.decode_token(access_token, "access")?;
        let stored_session = self
            .sessions
            .find_by_session_id(claims.session_id)
            .await?
            .ok_or(AuthError::SessionNotFound)?;

        if stored_session.revoked_at.is_some()
            || stored_session.subject_id != claims.sub
            || stored_session.access_expires_at < Utc::now()
        {
            return Err(AuthError::InvalidToken);
        }

        Ok(AccessContext {
            subject_id: claims.sub,
            login: claims.login,
            session_id: claims.session_id,
            issued_at: stored_session.issued_at,
            expires_at: stored_session.access_expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{JwtTokenConfig, JwtTokenService};
    use auth_core::domain::{entities::Identity, services::TokenService};
    use auth_repo_memory::InMemorySessionRepository;
    use uuid::Uuid;

    fn test_identity() -> Identity {
        Identity {
            id: Uuid::new_v4(),
            login: "tester".to_string(),
            email: Some("tester@example.com".to_string()),
            password_hash: "hash".to_string(),
            active: true,
        }
    }

    fn test_service() -> JwtTokenService<InMemorySessionRepository> {
        JwtTokenService::new(
            JwtTokenConfig {
                issuer: "auth-test".to_string(),
                secret: "super-secret-for-tests".to_string(),
                access_ttl_seconds: 300,
                refresh_ttl_seconds: 3600,
            },
            InMemorySessionRepository::default(),
        )
    }

    #[tokio::test]
    async fn issues_and_refreshes_tokens() {
        let service = test_service();
        let session = service.issue_for(test_identity()).await.unwrap();
        let refreshed = service
            .refresh(&session.access_token, &session.refresh_token)
            .await
            .unwrap();
        assert_eq!(session.session_id, refreshed.session_id);
        assert_eq!(session.subject_id, refreshed.subject_id);
        assert_eq!(session.token_type, refreshed.token_type);
    }

    #[tokio::test]
    async fn revocation_invalidates_session() {
        let service = test_service();
        let session = service.issue_for(test_identity()).await.unwrap();
        service.revoke(&session.access_token).await.unwrap();
        let result = service
            .refresh(&session.access_token, &session.refresh_token)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn introspection_returns_access_context() {
        let service = test_service();
        let session = service.issue_for(test_identity()).await.unwrap();
        let context = service.introspect(&session.access_token).await.unwrap();
        assert_eq!(context.session_id, session.session_id);
        assert_eq!(context.subject_id, session.subject_id);
    }
}
