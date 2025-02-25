use anyhow::Result;
use core::result::Result::Ok; // to shadow tonic::Code::Ok
use friends::profile::{edit_profile_request::Field, *};
use tonic::Code::*;
use util::{edit_profile, get_profile, new_account};

#[allow(unused)]
mod util;

#[tokio::test]
async fn test_get_profile_success() -> Result<()> {
    // Create a new user
    let (username, _, _) = new_account().await?;

    // Use the utility function to get profile
    let profile = get_profile(&username).await?;

    assert_eq!(profile.bio, "Test bio");
    assert_eq!(profile.city, "Test City");
    assert_eq!(profile.date_of_birth, Some(Date { year: 1990, month: 1, day: 1 }));

    Ok(())
}

#[tokio::test]
async fn test_edit_profile_unauthenticated() -> Result<()> {
    // No token provided in edit_profile call
    let response = edit_profile("", Field::Bio("New bio".to_string())).await;
    assert_eq!(response.unwrap_err().code(), Unauthenticated);

    Ok(())
}

#[tokio::test]
async fn test_edit_profile_invalid_token() -> Result<()> {
    // Invalid token provided
    let response = edit_profile("invalid token", Field::City("New City".to_string())).await;
    assert_eq!(response.unwrap_err().code(), Unauthenticated);

    Ok(())
}

#[tokio::test]
async fn test_edit_profile_success() -> Result<()> {
    // Create a new user
    let (username, _, token) = new_account().await?;

    // Edit the profile
    edit_profile(&token.token, Field::Bio("Updated bio".to_string())).await?;

    // Get and check the updated profile
    let updated_profile = get_profile(&username).await?;
    assert_eq!(updated_profile.bio, "Updated bio");

    Ok(())
}
