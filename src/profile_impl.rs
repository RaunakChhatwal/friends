use crate::entity;
use crate::middleware::lookup_extensions;
use crate::profile::{edit_profile_request::Field, *};
use crate::util::{anyhow_to_status, conn};
use anyhow::{Result, anyhow, bail};
use chrono::Datelike;
use sea_orm::*;
use tonic::{Request, Response, Status};

type TonicResult<T> = Result<Response<T>, Status>;

#[derive(Default)]
pub struct ProfileService;

impl crate::middleware::AuthenticatedEndpoints for ProfileService {
    fn authenticated_endpoints() -> Vec<&'static str> {
        vec!["EditProfile"]
    }
}

/// Implementation of get_profile functionality using anyhow for error handling
async fn get_profile(username: &str) -> Result<Profile> {
    entity::user::Entity::find_related()
        .filter(entity::user::Column::Username.eq(username.trim()))
        .one(&*conn)
        .await?
        .map(Into::into)
        .ok_or(Status::not_found(format!("Username {username} not found")).into())
}

/// Implementation of edit_profile functionality using anyhow for error handling
async fn edit_profile(
    txn: DatabaseTransaction, user: &entity::user::Model, field: Option<Field>,
) -> Result<()> {
    // Find profile for user
    let mut profile = entity::user::Entity::find_related()
        .filter(entity::user::Column::Id.eq(user.id))
        .one(&txn)
        .await?
        .ok_or(anyhow!("Expected profile for user {}", user.username))?
        .into_active_model();

    // Apply requested changes
    match field {
        Some(Field::Bio(new_bio)) => profile.bio = Set(new_bio),
        Some(Field::City(new_city)) => profile.city = Set(new_city),
        None => bail!(Status::invalid_argument("Either bio or city must be provided")),
    }

    // Update profile and commit transaction
    profile.update(&txn).await?;
    txn.commit().await?;

    Ok(())
}

#[tonic::async_trait]
impl profile_service_server::ProfileService for ProfileService {
    async fn get_profile(&self, request: Request<User>) -> TonicResult<Profile> {
        let username = request.into_inner().username;
        get_profile(&username).await.map(Response::new).map_err(anyhow_to_status)
    }

    async fn edit_profile(&self, mut request: Request<EditProfileRequest>) -> TonicResult<()> {
        let (txn, user) = lookup_extensions(request.extensions_mut()).map_err(anyhow_to_status)?;
        let field = request.into_inner().field;
        edit_profile(txn, &user, field).await.map(Response::new).map_err(anyhow_to_status)
    }
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
