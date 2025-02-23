use anyhow::{Context, Result};
use core::result::Result::Ok; // to shadow tonic::Code::Ok
use friends::auth::auth_service_client::AuthServiceClient;
use friends::auth::{LoginRequest, SignUpRequest};
use friends::channel;
use friends::profile::{Date, Profile};
use std::sync::atomic::{AtomicBool, Ordering};
use tonic::{Code::*, Request, transport::Channel};
use uuid::Uuid;

async fn client() -> Result<AuthServiceClient<Channel>> {
    let channel = channel().await.context("Failed to create channel")?;
    Ok(AuthServiceClient::new(channel))
}

fn sign_up_request(username: impl AsRef<str>, password: impl AsRef<str>) -> Request<SignUpRequest> {
    Request::new(SignUpRequest {
        username: username.as_ref().to_string(),
        password: password.as_ref().to_string(),
        profile: Some(Profile {
            bio: "Test bio".to_string(),
            city: "Test City".to_string(),
            date_of_birth: Some(Date { year: 1990, month: 1, day: 1 }),
        }),
    })
}

fn login_request(username: impl AsRef<str>, password: impl AsRef<str>) -> Request<LoginRequest> {
    Request::new(LoginRequest {
        username: username.as_ref().to_string(),
        password: password.as_ref().to_string(),
    })
}

#[tokio::test]
async fn test_sign_up_short_credentials() -> Result<()> {
    let mut client = client().await?;

    // Test too short username
    let request = sign_up_request("ab", "validPass123!");
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for short username")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    // Test too short password
    let username = format!("testuser_{}", Uuid::new_v4());
    let request = sign_up_request(&username, "short");
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for short password")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    return Ok(());
}

#[tokio::test]
async fn test_sign_up_profile_validation() -> Result<()> {
    let mut client = client().await?;

    // Test invalid date of birth (future date)
    let username = format!("testuser_{}", Uuid::new_v4());
    let mut request = sign_up_request(&username, "validPass123!");
    request.get_mut().profile.as_mut().unwrap().date_of_birth.as_mut().unwrap().year = 2026;
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for future date of birth")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    // Test invalid date of birth (invalid month)
    let mut request = sign_up_request(&username, "validPass123!");
    request.get_mut().profile.as_mut().unwrap().date_of_birth.as_mut().unwrap().month = 13;
    let response = client.sign_up(request).await;
    let error = response.err().context("Expected error for invalid month")?;
    assert_eq!(error.code(), InvalidArgument, "Expected InvalidArgument but got {error:?}");

    return Ok(());
}

#[tokio::test]
async fn test_sign_up_success() -> Result<()> {
    // Test successful sign up with unique username
    let username = format!("user_{}", Uuid::new_v4());
    let request = sign_up_request(&username, "validPass123!");
    let response = client().await?.sign_up(request).await;
    let token = response.context("Sign up request failed")?.into_inner();
    assert!(!token.token.is_empty(), "Received empty token for successful sign up");

    return Ok(());
}

// Don't recreate the same account
static TEST_ACCOUNT_CREATED: AtomicBool = AtomicBool::new(false);

// Share the same account to test login functionality on
async fn create_test_account(
    client: &mut AuthServiceClient<Channel>,
) -> (&'static str, &'static str) {
    let username = "testuser";
    let password = "validPass123!";

    let test_account_created = TEST_ACCOUNT_CREATED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err();

    if !test_account_created {
        let request = sign_up_request(username, password);
        client.sign_up(request).await.expect("Failed to create test account");
    }

    (username, password)
}

#[tokio::test]
async fn test_login_wrong_credentials() -> Result<()> {
    let mut client = client().await?;
    let (username, password) = create_test_account(&mut client).await;

    // Test wrong username
    let request = login_request("nonexistent", password);
    let response = client.login(request).await;
    let error = response.err().context("Expected error for non-existent user")?;
    assert_eq!(error.code(), NotFound, "Expected NotFound error but got {error:?}");

    // Test wrong password
    let request = login_request(username, "wrongPass123!");
    let response = client.login(request).await;
    let error = response.err().context("Expected error for wrong password")?;
    assert_eq!(error.code(), Unauthenticated, "Expected Unauthenticated error but got {error:?}");

    return Ok(());
}

#[tokio::test]
async fn test_login_success() -> Result<()> {
    let mut client = client().await?;
    let (username, password) = create_test_account(&mut client).await;

    // Try logging in with correct credentials
    let request = login_request(username, password);
    let response = client.login(request).await.context("Login request failed")?;
    let token = response.into_inner().token;
    assert!(!token.is_empty(), "Received empty token for successful login");

    return Ok(());
}
