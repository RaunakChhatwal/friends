use crate::auth::create_channel;
use crate::util::{LocalStorage, format_error, get_user_input};
use anyhow::{Context, Result};
use friends::profile::{
    EditProfileRequest, User, edit_profile_request::Field,
    profile_service_client::ProfileServiceClient,
};
use tonic::{Request, metadata::MetadataValue};

pub async fn view_profile() -> Result<()> {
    let mut profile_client = ProfileServiceClient::new(create_channel().await?);
    let username = get_user_input("Enter username to view: ")?;

    let request = Request::new(User { username });
    match profile_client.get_profile(request).await {
        Ok(response) => {
            let profile = response.into_inner();
            println!("\nProfile:");
            println!("Bio: {}", profile.bio);
            println!("City: {}", profile.city);
            if let Some(dob) = profile.date_of_birth {
                println!("Date of Birth: {}/{}/{}", dob.year, dob.month, dob.day);
            }
        }
        Err(status) => println!("Failed to get profile: {}", format_error(status)),
    }
    Ok(())
}

pub async fn edit_field(
    profile_client: &mut ProfileServiceClient<tonic::transport::Channel>,
    auth_header: &MetadataValue<tonic::metadata::Ascii>, choice: u32,
) -> Result<()> {
    match choice {
        1 => {
            let bio = get_user_input("Enter new bio: ")?;
            let edit_request = EditProfileRequest { field: Some(Field::Bio(bio)) };
            let mut request = Request::new(edit_request);
            request.metadata_mut().insert("authorization", auth_header.clone());

            match profile_client.edit_profile(request).await {
                Ok(_) => println!("Successfully updated bio"),
                Err(status) => println!("Failed to update bio: {}", format_error(status)),
            }
        }
        2 => {
            let city = get_user_input("Enter new city: ")?;
            let edit_request = EditProfileRequest { field: Some(Field::City(city)) };
            let mut request = Request::new(edit_request);
            request.metadata_mut().insert("authorization", auth_header.clone());

            match profile_client.edit_profile(request).await {
                Ok(_) => println!("Successfully updated city"),
                Err(status) => println!("Failed to update city: {}", format_error(status)),
            }
        }
        _ => println!("Invalid choice."),
    }
    Ok(())
}

pub async fn my_profile(storage: &LocalStorage) -> Result<()> {
    let mut profile_client = ProfileServiceClient::new(create_channel().await?);

    let auth_header = MetadataValue::try_from(&format!("Bearer {}", storage.login_token))
        .context("Authentication failed: Invalid token format")?;

    let mut request = Request::new(User { username: storage.username.clone() });
    request.metadata_mut().insert("authorization", auth_header.clone());

    let profile = match profile_client.get_profile(request).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            println!("Failed to get profile: {}", format_error(status));
            return Ok(());
        }
    };

    println!("\nYour Profile:");
    println!("1. Bio: {}", profile.bio);
    println!("2. City: {}", profile.city);
    if let Some(dob) = profile.date_of_birth {
        println!("Date of Birth: {}/{}/{}", dob.year, dob.month, dob.day);
    }

    let choice = get_user_input("\nEnter field number to edit (or press Enter to skip): ")?;
    if let Ok(num) = choice.parse::<u32>() {
        edit_field(&mut profile_client, &auth_header, num).await?;
    }

    Ok(())
}
