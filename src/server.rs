#![feature(let_chains)]

mod entity;
mod auth {
    tonic::include_proto!("auth");
}
mod profile {
    tonic::include_proto!("profile");
}

use anyhow::Result;
use auth::{auth_service_server::AuthServiceServer, *};
use chrono::Datelike;
use profile::{profile_service_server::ProfileServiceServer, *};
use sea_orm::*;
use std::{collections::HashMap, pin::Pin, sync::Arc, task::Poll};
use tonic::{Request, Response, Status, body::BoxBody};

fn connect_to_database() -> DatabaseConnection {
    let future = Database::connect(format!("sqlite://data.db?mode=rwc"));
    futures::executor::block_on(future).expect("Failed to connect to database")
}

lazy_static::lazy_static! {
    static ref conn: DatabaseConnection = connect_to_database();
}

impl Into<Profile> for entity::profile::Model {
    fn into(self) -> Profile {
        let Self { bio, date_of_birth, city, .. } = self;
        let year = date_of_birth.year() as u32;
        let month = date_of_birth.month();
        let day = date_of_birth.day();
        Profile { bio, date_of_birth: Some(Date { year, month, day }), city }
    }
}

type TonicResult<T> = Result<Response<T>, Status>;

#[derive(Default)]
pub struct ProfileService;

#[tonic::async_trait]
impl profile_service_server::ProfileService for ProfileService {
    async fn get_profile(&self, request: Request<User>) -> TonicResult<Profile> {
        let username = request.into_inner().username;
        let profile = entity::user::Entity::find_related()
            .filter(entity::user::Column::Username.eq(&username))
            .one(&*conn)
            .await
            .map_err(|_| Status::internal("Database error"))?
            .ok_or(Status::not_found(format!("Username {username} not found")))?
            .into();

        Ok(Response::new(profile))
    }

    async fn edit_profile(&self, mut request: Request<Profile>) -> TonicResult<()> {
        let (txn, user) = Self::lookup_extensions(request.extensions_mut())?;
        let mut profile = entity::user::Entity::find_related()
            .filter(entity::user::Column::Id.eq(user.id))
            .one(&*txn)
            .await
            .map_err(|_| Status::internal("Database error"))?
            .unwrap_or_else(|| panic!("Expected profile due to foreign key constraint"))
            .into_active_model();

        let Profile { bio: new_bio, city: new_city, .. } = request.into_inner();
        profile.bio = Set(new_bio);
        profile.city = Set(new_city);
        profile.update(&*txn).await.map_err(|_| Status::internal("Database error"))?;

        return Ok(Response::new(()));
    }
}

trait AuthenticatedService {
    fn authenticated_endpoints() -> Vec<&'static str>;

    fn lookup_extensions(
        extensions: &mut tonic::Extensions,
    ) -> Result<(Arc<DatabaseTransaction>, entity::user::Model), Status> {
        let txn = extensions
            .remove()
            .ok_or(Status::internal("Open transaction from auth middleware not found."))?;

        let user = extensions
            .remove()
            .ok_or(Status::internal("User info from auth middleware not found"))?;

        Ok((txn, user))
    }
}

impl AuthenticatedService for ProfileService {
    fn authenticated_endpoints() -> Vec<&'static str> {
        vec!["EditProfile"]
    }
}

#[derive(Clone)]
struct AuthMiddleware<S> {
    authenticated_endpoints: Arc<HashMap<&'static str, Vec<&'static str>>>,
    inner: Arc<std::sync::Mutex<S>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Claims {
    expiry: usize,
    subject: uuid::Uuid,
}

async fn auth_interceptor<Body>(request: &mut http::Request<Body>) -> Result<(), Status> {
    let header = request
        .headers()
        .get("authorization")
        .ok_or(Status::unauthenticated("Missing authorization header"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("Invalid bearer token: {error}"))?;

    let prefix = "Bearer ";
    if !header.starts_with(prefix) {
        return Err(Status::unauthenticated("Invalid bearer token"));
    }
    let token = &header[prefix.len()..];

    let key = jsonwebtoken::DecodingKey::from_secret("mcdonalds".as_bytes());
    let uuid = match jsonwebtoken::decode::<Claims>(token, &key, &Default::default()) {
        Ok(token_data) => token_data.claims.subject,
        Err(error) => return Err(Status::unauthenticated(error.to_string())),
    };

    let txn = conn.begin().await.map_err(|_| Status::internal("Database error"))?;
    let user = entity::user::Entity::find()
        .filter(entity::user::Column::Uuid.eq(uuid))
        .one(&txn)
        .await
        .map_err(|_| Status::internal("Database error"))?
        .ok_or(Status::not_found("Account not found"))?;

    request.extensions_mut().insert(Arc::new(txn)); // because Extensions::insert requires Clone
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
        if let [service, endpoint] = request.uri().path().split('/').collect::<Vec<_>>()[..] {
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
struct AuthLayer {
    authenticated_endpoints: Arc<HashMap<&'static str, Vec<&'static str>>>,
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

#[tonic::async_trait]
impl auth_service_server::AuthService for AuthService {
    async fn login(
        &self, request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let LoginRequest { username, password } = request.into_inner();

        // Find user by username
        let entity::user::Model { uuid, password_hash, .. } = entity::user::Entity::find()
            .filter(entity::user::Column::Username.eq(username))
            .one(&*conn)
            .await
            .map_err(|_| Status::internal("Database error"))?
            .ok_or_else(|| Status::not_found("Invalid username"))?;

        // Verify password in a blocking task since bcrypt is CPU-intensive
        let verification_task = move || bcrypt::verify(password, &password_hash);
        let valid = tokio::task::spawn_blocking(verification_task)
            .await
            .map_err(|_| Status::internal("Task join error"))?
            .map_err(|_| Status::unauthenticated("Failed to verify password"))?;

        if !valid {
            return Err(Status::unauthenticated("Invalid password"));
        }

        // Generate JWT token
        let claims = Claims {
            subject: uuid,
            expiry: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let key = jsonwebtoken::EncodingKey::from_secret("mcdonalds".as_bytes());
        let token = jsonwebtoken::encode(&Default::default(), &claims, &key)
            .map_err(|_| Status::internal("Failed to generate token"))?;

        Ok(Response::new(LoginResponse { token }))
    }

    async fn sign_up(
        &self, request: Request<SignUpRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let SignUpRequest { username, password, profile } = request.into_inner();

        // Start a transaction since we need to create both user and profile
        let txn = conn.begin().await.map_err(|_| Status::internal("Database error"))?;

        // Check if username already exists
        let existing_user = entity::user::Entity::find()
            .filter(entity::user::Column::Username.eq(&username))
            .one(&txn)
            .await
            .map_err(|_| Status::internal("Database error"))?;

        if existing_user.is_some() {
            return Err(Status::already_exists("Username already taken"));
        }

        // Hash password in a blocking task since bcrypt is CPU-intensive
        let hash_task = move || bcrypt::hash(password, bcrypt::DEFAULT_COST);
        let password_hash = tokio::task::spawn_blocking(hash_task)
            .await
            .map_err(|_| Status::internal("Task join error"))?
            .map_err(|_| Status::internal("Failed to hash password"))?;

        // Create profile first since user has a foreign key to it
        let profile = entity::profile::ActiveModel {
            bio: Set(profile.as_ref().map(|p| p.bio.clone()).unwrap_or_default()),
            date_of_birth: Set(profile
                .as_ref()
                .and_then(|p| p.date_of_birth.as_ref())
                .map(|d| chrono::NaiveDate::from_ymd_opt(d.year as i32, d.month, d.day).unwrap())
                .unwrap_or_else(|| chrono::Utc::now().naive_utc().date())),
            city: Set(profile.as_ref().map(|p| p.city.clone()).unwrap_or_default()),
            ..Default::default()
        };
        let profile = profile.insert(&txn).await.map_err(|_| Status::internal("Database error"))?;

        // Create user with reference to profile
        let uuid = uuid::Uuid::new_v4();
        let user = entity::user::ActiveModel {
            uuid: Set(uuid),
            username: Set(username),
            password_hash: Set(password_hash),
            profile: Set(profile.id),
            ..Default::default()
        };
        let user = user.insert(&txn).await.map_err(|_| Status::internal("Database error"))?;

        // Update profile with reference back to user
        let mut profile: entity::profile::ActiveModel = profile.into();
        profile.user = Set(user.id);
        profile.update(&txn).await.map_err(|_| Status::internal("Database error"))?;

        // Commit transaction
        txn.commit().await.map_err(|_| Status::internal("Database error"))?;

        // Generate JWT token
        let claims = Claims {
            subject: uuid,
            expiry: (chrono::Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
        };

        let key = jsonwebtoken::EncodingKey::from_secret("mcdonalds".as_bytes());
        let token = jsonwebtoken::encode(&Default::default(), &claims, &key)
            .map_err(|_| Status::internal("Failed to generate token"))?;

        Ok(Response::new(LoginResponse { token }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let address = "0.0.0.0:50051".parse()?;

    let profile_service = ProfileServiceServer::new(ProfileService::default());
    let auth_service = AuthServiceServer::new(AuthService::default());

    let mut authenticated_endpoints = HashMap::new();
    authenticated_endpoints
        .insert("profile.ProfileService", ProfileService::authenticated_endpoints());
    let auth_layer = AuthLayer { authenticated_endpoints: Arc::new(authenticated_endpoints) };

    tonic::transport::Server::builder()
        .layer(tower::ServiceBuilder::new().layer(auth_layer).into_inner())
        .add_service(profile_service)
        .add_service(auth_service)
        .serve(address)
        .await
        .map_err(Into::into)
}
