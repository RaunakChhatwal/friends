use crate::entity;
use crate::profile::*;
use crate::util::{conn, to_internal_db_err};
use chrono::Datelike;
use sea_orm::*;
use tonic::{Request, Response, Status};

type TonicResult<T> = Result<Response<T>, Status>;

#[derive(Default)]
pub struct ProfileService;

impl crate::auth_impl::AuthenticatedEndpoints for ProfileService {
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
            .map_err(to_internal_db_err)?
            .ok_or(Status::not_found(format!("Username {username} not found")))?
            .into();

        Ok(Response::new(profile))
    }

    async fn edit_profile(&self, mut request: Request<EditProfileRequest>) -> TonicResult<()> {
        let (txn, user) = crate::auth_impl::lookup_extensions(request.extensions_mut())?;
        let mut profile = entity::user::Entity::find_related()
            .filter(entity::user::Column::Id.eq(user.id))
            .one(&txn)
            .await
            .map_err(to_internal_db_err)?
            .unwrap_or_else(|| panic!("Expected profile due to foreign key constraint"))
            .into_active_model();

        let EditProfileRequest { bio: new_bio, city: new_city } = request.into_inner();
        profile.bio = Set(new_bio);
        profile.city = Set(new_city);
        profile.update(&txn).await.map_err(to_internal_db_err)?;

        txn.commit().await.map_err(to_internal_db_err)?;
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
