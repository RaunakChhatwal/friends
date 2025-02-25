use crate::entity;
use crate::internal;
use crate::util::conn;
use atomic_take::AtomicTake;
use futures::FutureExt;
use sea_orm::*;
use std::{collections::HashMap, env, pin::Pin, sync::Arc, task::Poll};
use tonic::{Code::Internal, Status, body::BoxBody};

lazy_static::lazy_static! {
    pub static ref JWT_SECRET: String = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
}

pub trait AuthenticatedEndpoints {
    fn authenticated_endpoints() -> Vec<&'static str> {
        vec![]
    }
}

pub fn lookup_extensions(
    extensions: &mut tonic::Extensions,
) -> Result<(DatabaseTransaction, entity::user::Model), Status> {
    let txn = extensions
        .remove::<Arc<AtomicTake<_>>>()
        .as_ref()
        .map(AsRef::as_ref)
        .and_then(AtomicTake::take)
        .ok_or(internal!("Transaction not present in request extensions"))?;

    let user = extensions.remove().ok_or(internal!("UUID not present in request extensions"))?;

    Ok((txn, user))
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    authenticated_endpoints: Arc<HashMap<&'static str, Vec<&'static str>>>,
    inner: Arc<std::sync::Mutex<S>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Claims {
    pub exp: usize,      // expiry
    pub sub: uuid::Uuid, // subject
}

async fn auth_interceptor<Body>(request: &mut http::Request<Body>) -> Result<(), Status> {
    let header = request
        .headers()
        .get("authorization")
        .ok_or(Status::unauthenticated("Missing authorization header"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("Invalid bearer token"))?;

    let prefix = "Bearer ";
    if !header.starts_with(prefix) {
        return Err(Status::unauthenticated("Invalid bearer token"));
    }
    let token = &header[prefix.len()..];

    let key = jsonwebtoken::DecodingKey::from_secret(JWT_SECRET.as_bytes());
    let uuid = match jsonwebtoken::decode::<Claims>(token, &key, &Default::default()) {
        Ok(token_data) => token_data.claims.sub,
        Err(error) => return Err(Status::unauthenticated(error.to_string())),
    };

    let txn =
        conn.begin().await.map_err(|error| internal!("Error starting transaction: {error}"))?;
    let user = entity::user::Entity::find()
        .filter(entity::user::Column::Uuid.eq(uuid))
        .one(&txn)
        .await
        .map_err(|error| internal!("Error running query: {error}"))?
        .ok_or(Status::not_found("Account not found"))?;

    let txn_extension = Arc::new(AtomicTake::new(txn)); // because Extensions::insert requires Clone and Send
    request.extensions_mut().insert(txn_extension);
    request.extensions_mut().insert(user);
    return Ok(());
}

impl<S, Payload> tower::Service<http::Request<Payload>> for AuthMiddleware<S>
where
    S: tower::Service<http::Request<Payload>, Response = http::Response<BoxBody>> + Send + 'static,
    S::Future: Send + 'static,
    Payload: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.lock().unwrap().poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<Payload>) -> Self::Future {
        let mut authenticate = false;
        if let ["", service, endpoint] = request.uri().path().split('/').collect::<Vec<_>>()[..] {
            if let Some(endpoints) = self.authenticated_endpoints.get(service) {
                if endpoints.contains(&endpoint) {
                    authenticate = true;
                }
            }
        };

        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            if authenticate && let Err(denial) = auth_interceptor(&mut request).await {
                return Ok(denial.into_http());
            }

            let future = inner.lock().unwrap().call(request); // don't await while lock held
            future.await
        })
    }
}

#[derive(Clone)]
pub struct AuthLayer {
    pub authenticated_endpoints: Arc<HashMap<&'static str, Vec<&'static str>>>,
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AuthMiddleware {
            authenticated_endpoints: Arc::clone(&self.authenticated_endpoints),
            inner: Arc::new(std::sync::Mutex::new(service)),
        }
    }
}

#[derive(Clone)]
pub struct InternalErrorMiddleware<S> {
    inner: S,
}

fn intercept_internal_error(response: http::Response<BoxBody>) -> http::Response<BoxBody> {
    return Status::from_header_map(response.headers())
        .map(|status| status.code() == Internal)
        .unwrap_or(false)
        .then_some(Status::internal("An unexpected error occurred.").into_http())
        .unwrap_or(response);
}

impl<S, Payload> tower::Service<http::Request<Payload>> for InternalErrorMiddleware<S>
where
    S: tower::Service<http::Request<Payload>, Response = http::Response<BoxBody>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<Payload>) -> Self::Future {
        Box::pin(self.inner.call(request).map(|result| result.map(intercept_internal_error)))
    }
}

#[derive(Clone, Default)]
pub struct InternalErrorLayer;

impl<S> tower::Layer<S> for InternalErrorLayer {
    type Service = InternalErrorMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        InternalErrorMiddleware { inner: service }
    }
}
