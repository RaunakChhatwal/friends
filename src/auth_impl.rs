use crate::auth::*;
use crate::entity;
use crate::internal;
use crate::profile::*;
use crate::util::{conn, to_internal_db_err};
use atomic_take::AtomicTake;
use sea_orm::*;
use std::{collections::HashMap, pin::Pin, sync::Arc, task::Poll};
use tonic::{Request, Response, Status, body::BoxBody};

lazy_static::lazy_static! {
    static ref JWT_SECRET: String = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
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
        .ok_or(internal!("Resource from middleware not found"))?;

    let user = extensions.remove().ok_or(internal!("Resource from middleware not found"))?;

    Ok((txn, user))
}

#[derive(Clone)]
pub struct AuthMiddleware<S> {
    authenticated_endpoints: Arc<HashMap<&'static str, Vec<&'static str>>>,
    inner: Arc<std::sync::Mutex<S>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    exp: usize,      // expiry
    sub: uuid::Uuid, // subject
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

    let txn = conn.begin().await.map_err(to_internal_db_err)?;
    let user = entity::user::Entity::find()
        .filter(entity::user::Column::Uuid.eq(uuid))
        .one(&txn)
        .await
        .map_err(to_internal_db_err)?
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

#[derive(Default)]
pub struct AuthService;

impl AuthenticatedEndpoints for AuthService {}

#[tonic::async_trait]
impl auth_service_server::AuthService for AuthService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<Token>, Status> {
        let LoginRequest { username, password } = request.into_inner();

        // Find user by username
        let entity::user::Model { uuid, password_hash, .. } = entity::user::Entity::find()
            .filter(entity::user::Column::Username.eq(username.trim()))
            .one(&*conn)
            .await
            .map_err(to_internal_db_err)?
            .ok_or_else(|| Status::not_found("Invalid username"))?;

        // Verify password in a blocking task since bcrypt is CPU-intensive
        let verification_task = move || bcrypt::verify(password.trim(), &password_hash);
        let valid = tokio::task::spawn_blocking(verification_task)
            .await
            .map_err(|_| internal!("Task join error"))?
            .map_err(|_| Status::unauthenticated("Failed to verify password"))?;

        if !valid {
            return Err(Status::unauthenticated("Invalid password"));
        }

        // Generate JWT token
        let claims = Claims {
            sub: uuid,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let key = jsonwebtoken::EncodingKey::from_secret(JWT_SECRET.as_bytes());
        let token = jsonwebtoken::encode(&Default::default(), &claims, &key)
            .map_err(|_| internal!("Failed to generate token"))?;

        Ok(Response::new(Token { token }))
    }

    async fn sign_up(&self, request: Request<SignUpRequest>) -> Result<Response<Token>, Status> {
        let SignUpRequest { username, password, profile } = request.into_inner();

        let username = username.trim();
        let (bio, city, date_of_birth) = validate_profile(profile)?;

        // Start a transaction since we need to create both user and profile
        let txn = conn.begin().await.map_err(to_internal_db_err)?;

        // Check if username already exists
        let existing_user = entity::user::Entity::find()
            .filter(entity::user::Column::Username.eq(username))
            .one(&txn)
            .await
            .map_err(to_internal_db_err)?;

        if existing_user.is_some() {
            return Err(Status::already_exists("Username already taken"));
        }

        // Hash password in a blocking task since bcrypt is CPU-intensive
        let hash_task = move || bcrypt::hash(password.trim(), bcrypt::DEFAULT_COST);
        let password_hash = tokio::task::spawn_blocking(hash_task)
            .await
            .map_err(|_| internal!("Task join error"))?
            .map_err(|_| internal!("Failed to hash password"))?;

        // Create user first since profile now references it
        let uuid = uuid::Uuid::new_v4();
        let user = entity::user::ActiveModel {
            uuid: Set(uuid),
            username: Set(username.into()),
            password_hash: Set(password_hash),
            ..Default::default()
        };
        let user = user.insert(&txn).await.map_err(to_internal_db_err)?;

        // Create profile with reference to user
        let profile = entity::profile::ActiveModel {
            bio: Set(bio),
            date_of_birth: Set(date_of_birth),
            city: Set(city),
            user: Set(user.id),
            ..Default::default()
        };
        profile.insert(&txn).await.map_err(to_internal_db_err)?;

        // Commit transaction
        txn.commit().await.map_err(to_internal_db_err)?;

        // Generate JWT token
        let claims = Claims {
            sub: uuid,
            exp: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let key = jsonwebtoken::EncodingKey::from_secret(JWT_SECRET.as_bytes());
        let token = jsonwebtoken::encode(&Default::default(), &claims, &key)
            .map_err(|_| internal!("Failed to generate token"))?;

        Ok(Response::new(Token { token }))
    }
}

fn validate_profile(
    profile: Option<Profile>,
) -> Result<(String, String, chrono::NaiveDate), Status> {
    let Some(Profile { date_of_birth, bio, city }) = profile else {
        return Err(Status::invalid_argument("Profile is required"));
    };

    let Some(Date { year, month, day }) = date_of_birth else {
        return Err(Status::invalid_argument("Date of birth is required"));
    };

    let date_of_birth = chrono::NaiveDate::from_ymd_opt(year as i32, month, day)
        .ok_or(Status::invalid_argument("Invalid date of birth"))?;

    let today = chrono::Utc::now().naive_utc().date();
    let age = today
        .years_since(date_of_birth)
        .ok_or(Status::invalid_argument("Invalid date of birth: cannot be in the future"))?;

    if age < 13 {
        return Err(Status::permission_denied("User must be at least 13 years old"));
    }

    Ok((bio, city, date_of_birth))
}
