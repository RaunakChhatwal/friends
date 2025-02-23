use anyhow::{Context, Result};
use core::result::Result::Ok; // to shadow tonic::Code::Ok
use friends::auth::SignUpRequest;
use friends::auth::auth_service_client::AuthServiceClient;
use friends::client;
use friends::profile::{Date, Profile};
use tonic::{Code::*, Request};
use uuid::Uuid;

fn sign_up_request(username: String, password: String, birth_year: u32) -> Request<SignUpRequest> {
    Request::new(SignUpRequest {
        username,
        password,
        profile: Some(Profile {
            bio: "Test bio".to_string(),
            city: "Test City".to_string(),
            date_of_birth: Some(Date { year: birth_year, month: 1, day: 1 }),
        }),
    })
}

#[tokio::test]
async fn test_sign_up_username_validation() -> Result<()> {
    let channel = client().await.context("Failed to create channel")?;
    let mut client = AuthServiceClient::new(channel);

    // Test empty username
    let request = sign_up_request("".to_string(), "validPass123!".to_string(), 1990);
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for empty username")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument error but got {error:?}");

    // Test too short username
    let request = sign_up_request("ab".to_string(), "validPass123!".to_string(), 1990);
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for short username")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");
    Ok(())
}

#[tokio::test]
async fn test_sign_up_password_validation() -> Result<()> {
    let channel = client().await.context("Failed to create channel")?;
    let mut client = AuthServiceClient::new(channel);

    // Test empty password
    let username = format!("testuser_{}", Uuid::new_v4());
    let request = sign_up_request(username, "".to_string(), 1990);
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for empty password")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    // Test too short password
    let username = format!("testuser_{}", Uuid::new_v4());
    let request = sign_up_request(username, "short".to_string(), 1990);
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for short password")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");
    Ok(())
}

#[tokio::test]
async fn test_sign_up_profile_validation() -> Result<()> {
    let channel = client().await.context("Failed to create channel")?;
    let mut client = AuthServiceClient::new(channel);

    // Test invalid date of birth (future date)
    let username = format!("testuser_{}", Uuid::new_v4());
    let request = sign_up_request(username, "validPass123!".to_string(), 2025);
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for future date of birth")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    // Test invalid date of birth (invalid month)
    let username = format!("testuser_{}", Uuid::new_v4());
    let mut request = sign_up_request(username, "validPass123!".to_string(), 1990);
    request.get_mut().profile.as_mut().unwrap().date_of_birth.as_mut().unwrap().month = 13;
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for invalid month")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");
    Ok(())
}

#[tokio::test]
async fn test_sign_up_success() -> Result<()> {
    let channel = client().await.context("Failed to create channel")?;
    let mut client = AuthServiceClient::new(channel);

    // Test successful sign up with unique username
    let username = format!("user_{}", Uuid::new_v4());
    let request = sign_up_request(username, "validPass123!".to_string(), 1990);
    let response = client.sign_up(request).await;
    let token = response.context("Sign up request failed")?.into_inner();
    assert!(!token.token.is_empty(), "Received empty token for successful sign up");
    Ok(())
}
