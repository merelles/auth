use std::{
    future::{ready, Ready},
    rc::Rc,
};

use actix_service::{Service, Transform};
use actix_web::{
    body::EitherBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    Error, HttpMessage, HttpResponse,
};
use auth_client::AuthClient;
use auth_core::domain::{commands::IntrospectTokenCommand, entities::AccessContext};
use futures_util::future::LocalBoxFuture;

#[derive(Clone)]
pub struct AuthMiddleware<C> {
    client: C,
}

impl<C> AuthMiddleware<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

pub fn access_context(req: &ServiceRequest) -> Option<AccessContext> {
    req.extensions().get::<AccessContext>().cloned()
}

impl<S, B, C> Transform<S, ServiceRequest> for AuthMiddleware<C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: AuthClient + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S, C>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            client: self.client.clone(),
        }))
    }
}

pub struct AuthMiddlewareService<S, C> {
    service: Rc<S>,
    client: C,
}

impl<S, B, C> Service<ServiceRequest> for AuthMiddlewareService<S, C>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
    C: AuthClient + Clone + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client = self.client.clone();
        let service = self.service.clone();

        Box::pin(async move {
            let Some(header_value) = req.headers().get(header::AUTHORIZATION) else {
                let response = req.into_response(HttpResponse::Unauthorized().finish());
                return Ok(response.map_into_right_body());
            };

            let Ok(header_value) = header_value.to_str() else {
                let response = req.into_response(HttpResponse::Unauthorized().finish());
                return Ok(response.map_into_right_body());
            };

            let Some(token) = header_value.strip_prefix("Bearer ") else {
                let response = req.into_response(HttpResponse::Unauthorized().finish());
                return Ok(response.map_into_right_body());
            };

            let context = match client
                .introspect(IntrospectTokenCommand {
                    access_token: token.to_string(),
                })
                .await
            {
                Ok(context) => context,
                Err(_) => {
                    let response = req.into_response(HttpResponse::Unauthorized().finish());
                    return Ok(response.map_into_right_body());
                }
            };

            req.extensions_mut().insert(context);
            let response = service.call(req).await?;
            Ok(response.map_into_left_body())
        })
    }
}
