use crate::entity;
use crate::profile::{edit_profile_request::Field, *};
use crate::util::conn;
use crate::{error_running_query, internal};
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

#[tonic::async_trait]
impl profile_service_server::ProfileService for ProfileService {
    async fn get_profile(&self, request: Request<User>) -> TonicResult<Profile> {
        let username = request.into_inner().username;
        let profile = entity::user::Entity::find_related()
            .filter(entity::user::Column::Username.eq(username.trim()))
            .one(&*conn)
            .await
            .map_err(error_running_query!())?
            .ok_or(Status::not_found(format!("Username {username} not found")))?
            .into();

        Ok(Response::new(profile))
    }

    async fn edit_profile(&self, mut request: Request<EditProfileRequest>) -> TonicResult<()> {
        let (txn, user) = crate::middleware::lookup_extensions(request.extensions_mut())?;

        let mut profile = entity::user::Entity::find_related()
            .filter(entity::user::Column::Id.eq(user.id))
            .one(&txn)
            .await
            .map_err(error_running_query!())?
            .ok_or(internal!("Expected profile for user {}", user.username))?
            .into_active_model();

        match request.into_inner().field {
            Some(Field::Bio(new_bio)) => profile.bio = Set(new_bio),
            Some(Field::City(new_city)) => profile.city = Set(new_city),
            None => return Err(Status::invalid_argument("Either bio or city must be provided")),
        }

        profile.update(&txn).await.map_err(error_running_query!())?;
        txn.commit().await.map_err(|error| internal!("Error commiting transaction: {error}"))?;
        return Ok(Response::new(()));
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
