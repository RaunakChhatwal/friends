use anyhow::{Context, Result};
use friends::auth::{auth_service_client::AuthServiceClient, *};
use friends::profile::edit_profile_request::Field;
use friends::profile::{profile_service_client::ProfileServiceClient, *};
use std::sync::atomic::{AtomicBool, Ordering};
use tonic::{Code::NotFound, Request, Status, transport::Channel};
use uuid::Uuid;

// lazy_static::lazy_static! {
//     static ref channel: Channel = {
//         let address =
//             format!("http://localhost:{}", std::env::var("PORT").unwrap_or("50051".into()));
//         let endpoint = Channel::from_shared(address).expect("Invalid address URL");
//         futures::executor::block_on(endpoint.connect()).expect("Failed to create channel")
//     };
// }

pub async fn channel() -> Channel {
    let address = format!("http://localhost:{}", std::env::var("PORT").unwrap_or("50051".into()));
    let endpoint = Channel::from_shared(address).expect("Invalid address URL");
    endpoint.connect().await.expect("Failed to create channel")
}

/// Creates a new account with a unique username and returns the credentials and token.
pub async fn new_account() -> Result<(String, String, Token), Status> {
    let username = format!("testuser_{}", Uuid::new_v4());
    let password = format!("validPass{}!", Uuid::new_v4());
    let token = sign_up(&username, &password, 1990, 1, 1).await?;
    Ok((username, password, token))
}

pub async fn sign_up(
    username: impl AsRef<str>, password: impl AsRef<str>, year: u32, month: u32, day: u32,
) -> Result<Token, Status> {
    let profile = Profile {
        bio: "Test bio".to_string(),
        city: "Test City".to_string(),
        date_of_birth: Some(Date { year, month, day }),
    };
    let request = SignUpRequest {
        username: username.as_ref().to_string(),
        password: password.as_ref().to_string(),
        profile: Some(profile),
    };

    let mut client = AuthServiceClient::new(channel().await);
    let response = client.sign_up(Request::new(request)).await?;
    Ok(response.into_inner())
}

pub async fn log_in(username: impl AsRef<str>, password: impl AsRef<str>) -> Result<Token, Status> {
    let request = LogInRequest {
        username: username.as_ref().to_string(),
        password: password.as_ref().to_string(),
    };

    let mut client = AuthServiceClient::new(channel().await);
    let response = client.log_in(Request::new(request)).await?;
    Ok(response.into_inner())
}

// Profile utility functions

pub async fn get_profile(username: impl AsRef<str>) -> Result<Profile, Status> {
    let mut client = ProfileServiceClient::new(channel().await);
    let request = User { username: username.as_ref().to_string() };
    let response = client.get_profile(Request::new(request)).await?;
    Ok(response.into_inner())
}

pub async fn edit_profile(token: impl AsRef<str>, field: Field) -> Result<(), Status> {
    let mut client = ProfileServiceClient::new(channel().await);
    let mut request = Request::new(EditProfileRequest { field: Some(field) });

    // Add authorization header
    let bearer = format!("Bearer {}", token.as_ref()).parse().expect("Token should be ascii");
    request.metadata_mut().insert("authorization", bearer);

    client.edit_profile(request).await.map(drop)
}
