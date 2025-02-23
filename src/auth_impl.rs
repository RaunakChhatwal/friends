use crate::auth::*;
use crate::entity;
use crate::internal;
use crate::middleware::{AuthenticatedEndpoints, Claims, JWT_SECRET};
use crate::profile::*;
use crate::util::{conn, to_internal_db_err};
use regex::Regex;
use sea_orm::*;
use tonic::{Request, Response, Status};

#[derive(Default)]
pub struct AuthService;

impl AuthenticatedEndpoints for AuthService {}

fn validate_username(username: &str) -> Result<(), Status> {
    if username.len() < 3 || username.len() > 64 {
        return Err(Status::invalid_argument("Username must be between 3 and 30 characters long"));
    }

    let regex = Regex::new(r"^[a-zA-Z0-9_-]+$").expect("Invalid regex");
    if !regex.is_match(username) {
        let message = "Username may only contain letters, numbers, underscores, and hyphens";
        return Err(Status::invalid_argument(message));
    }

    return Ok(());
}

fn validate_password(password: &str) -> Result<(), Status> {
    if password.len() < 8 {
        return Err(Status::invalid_argument("Password must be between 8 and 72 characters long"));
    }

    if password.chars().all(|chr| chr.is_ascii_lowercase()) {
        let message = "Password must contain at least one uppercase letter";
        return Err(Status::invalid_argument(message));
    }

    if password.chars().all(|chr| chr.is_ascii_uppercase()) {
        let message = "Password must contain at least one lowercase letter";
        return Err(Status::invalid_argument(message));
    }

    if !password.chars().any(|chr| chr.is_ascii_digit()) {
        return Err(Status::invalid_argument("Password must contain at least one number"));
    }

    if password.contains(char::is_whitespace) {
        return Err(Status::invalid_argument("Password cannot contain whitespace"));
    }

    return Ok(());
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
        return Err(Status::invalid_argument("User must be at least 13 years old"));
    }

    Ok((bio, city, date_of_birth))
}

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
        validate_username(username)?;
        validate_password(password.trim())?;
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
