use anyhow::{Context, Result};
use core::result::Result::Ok; // to shadow tonic::Code::Ok
use tonic::Code::*;
use util::{log_in, new_account, sign_up};
use uuid::Uuid;

#[allow(unused)]
mod util;

#[tokio::test]
async fn test_sign_up_short_credentials() -> Result<()> {
    // Test too short username
    let response = sign_up("ab", "validPass123!", 1990, 1, 1).await;
    assert_eq!(response.unwrap_err().code(), InvalidArgument);

    // Test too short password
    let username = format!("testuser_{}", Uuid::new_v4());
    let response = sign_up(username, "short", 1990, 1, 1).await;
    assert_eq!(response.unwrap_err().code(), InvalidArgument);

    Ok(())
}

#[tokio::test]
async fn test_sign_up_profile_validation() -> Result<()> {
    // Test invalid date of birth (future date)
    let username = format!("testuser_{}", Uuid::new_v4());

    // Use sign_up directly with invalid year
    let response = sign_up(username.clone(), "validPass123!", 2026, 1, 1).await;
    assert_eq!(response.unwrap_err().code(), InvalidArgument);

    // Test invalid date of birth (invalid month)
    let response = sign_up(username, "validPass123!", 1990, 13, 1).await;
    assert_eq!(response.unwrap_err().code(), InvalidArgument);

    Ok(())
}

#[tokio::test]
async fn test_sign_up_success() -> Result<()> {
    // Test successful sign up with unique username
    let (_, _, token) = new_account().await?;
    assert!(!token.token.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_login_wrong_credentials() -> Result<()> {
    // Create a new user first
    let (username, password, _) = new_account().await?;

    // Test wrong username
    let response = log_in("nonexistent", password).await;
    assert_eq!(response.unwrap_err().code(), NotFound);

    // Test wrong password
    let response = log_in(&username, "wrongPass123!").await;
    assert_eq!(response.unwrap_err().code(), Unauthenticated);

    Ok(())
}

#[tokio::test]
async fn test_login_success() -> Result<()> {
    // Create a new user and try logging in
    let (username, password, _) = new_account().await?;

    // Try logging in with correct credentials
    let response = log_in(&username, password).await.context("Login request failed")?;
    assert!(!response.token.is_empty());

    Ok(())
}
