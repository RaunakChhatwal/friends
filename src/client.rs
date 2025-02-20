include!("mod.rs");

use anyhow::{Context, Result};
use auth::{LoginRequest, auth_service_client::AuthServiceClient};
use profile::{EditProfileRequest, profile_service_client::ProfileServiceClient};
use tonic::{Request, metadata::MetadataValue, transport::Channel};

#[tokio::main]
async fn main() -> Result<()> {
    let channel = Channel::from_static("http://0.0.0.0:50051")
        .connect()
        .await
        .context("Failed to connect to server")?;

    // First login to get a fresh token
    let mut auth_client = AuthServiceClient::new(channel.clone());
    let login_request =
        LoginRequest { username: String::from("testuser2"), password: String::from("mcdonalds") };

    let response = auth_client.login(login_request).await.context("Failed to login")?;
    let token = response.into_inner().token;
    println!("Successfully logged in!");

    // Now use the token to update profile
    let mut profile_client = ProfileServiceClient::new(channel);

    // Create the authorization header
    let bearer_token = format!("Bearer {}", token);
    let auth_header = MetadataValue::try_from(&bearer_token).context("Invalid token for header")?;

    // Create edit profile request
    let edit_request = EditProfileRequest { bio: String::from(""), city: String::from("") };

    // Create request with authorization
    let mut request = Request::new(edit_request);
    request.metadata_mut().insert("authorization", auth_header);

    // Try to update the profile
    let result = profile_client.edit_profile(request).await;
    match result {
        Ok(_) => println!("Successfully updated profile"),
        Err(status) => println!("Failed to update profile: {}", status.message()),
    }

    Ok(())
}
