include!("lib.rs");

use crate::profile::edit_profile_request::Field;
use anyhow::{Context, Result};
use auth::{LoginRequest, SignUpRequest, auth_service_client::AuthServiceClient};
use chrono::{Datelike, NaiveDate};
use profile::{EditProfileRequest, User, profile_service_client::ProfileServiceClient};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tonic::{Request, Status, metadata::MetadataValue, transport::Channel};

async fn client() -> Result<Channel> {
    Channel::from_static("http://0.0.0.0:50051").connect().await.context("Failed to create channel")
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalStorage {
    username: String,
    login_token: String,
}

impl LocalStorage {
    fn load() -> Option<Self> {
        let path = Path::new("./local_storage.json");
        if !path.exists() {
            return None;
        }

        fs::read_to_string(path).ok().and_then(|data| serde_json::from_str(&data).ok())
    }

    fn store(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write("./local_storage.json", json)?;
        Ok(())
    }
}

fn format_error(status: Status) -> String {
    format!("{}: {}", status.code(), status.message())
}

fn get_user_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

async fn log_in() -> Result<Option<LocalStorage>> {
    let mut auth_client = AuthServiceClient::new(client().await?);

    let username = get_user_input("Enter username: ")?;
    let password = get_user_input("Enter password: ")?;

    let login_request = LoginRequest { username: username.clone(), password };
    match auth_client.login(login_request).await {
        Ok(response) => {
            println!("Successfully logged in!");
            let token = response.into_inner().token;
            let storage = LocalStorage { username, login_token: token };
            storage.store()?;
            Ok(Some(storage))
        }
        Err(status) => {
            println!("Login failed: {}", format_error(status));
            Ok(None)
        }
    }
}

async fn sign_up() -> Result<Option<LocalStorage>> {
    let mut auth_client = AuthServiceClient::new(client().await?);
    let mut profile_client = ProfileServiceClient::new(client().await?);

    let username = loop {
        let username = get_user_input("Choose a username: ")?;

        // Check if username exists
        let check_request = Request::new(User { username: username.clone() });
        match profile_client.get_profile(check_request).await {
            Ok(_) => {
                println!("Username already exists. Please choose another one.");
                continue;
            }
            Err(status) if status.code() == tonic::Code::NotFound => {
                break username;
            }
            Err(status) => {
                println!("Error checking username: {}", format_error(status));
                return Ok(None);
            }
        }
    };

    // Username is available, get profile info
    println!("\nLet's set up your profile:");
    let bio = get_user_input("Enter your bio: ")?;
    let city = get_user_input("Enter your city: ")?;

    // Get date of birth
    let date_of_birth = loop {
        let input = get_user_input("\nEnter your date of birth (YYYY-MM-DD): ")?;
        match NaiveDate::parse_from_str(&input, "%Y-%m-%d") {
            Ok(date) => {
                break Some(profile::Date {
                    year: date.year() as u32,
                    month: date.month(),
                    day: date.day(),
                });
            }
            _ => println!("Please enter a valid date in YYYY-MM-DD format"),
        }
    };

    let password = loop {
        let password = get_user_input("\nChoose a password: ")?;
        let confirm = get_user_input("Confirm password: ")?;
        if password == confirm {
            break password;
        }
        println!("Passwords don't match. Please try again.");
    };

    let profile = Some(profile::Profile { bio, city, date_of_birth });

    loop {
        let signup_request = SignUpRequest {
            username: username.clone(),
            password: password.clone(),
            profile: profile.clone(),
        };

        match auth_client.sign_up(signup_request).await {
            Ok(response) => {
                println!("Successfully signed up!");
                let token = response.into_inner().token;
                let storage = LocalStorage { username: username.clone(), login_token: token };
                storage.store()?;
                return Ok(Some(storage));
            }
            Err(status) => {
                println!("Signup failed: {}", format_error(status));
                println!("Please try again with a different username.");
                break;
            }
        }
    }

    Ok(None)
}

async fn view_profile() -> Result<()> {
    let mut profile_client = ProfileServiceClient::new(client().await?);
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

async fn edit_field(
    profile_client: &mut ProfileServiceClient<Channel>,
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

async fn my_profile(storage: &LocalStorage) -> Result<()> {
    let mut profile_client = ProfileServiceClient::new(client().await?);

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

async fn main_menu() -> Result<Option<String>> {
    loop {
        println!("\nChoose an option:");
        println!("1. Login");
        println!("2. Sign up");
        println!("3. View profile");
        println!("4. Exit");

        let choice = get_user_input("Enter your choice (1-4): ")?;

        match choice.as_str() {
            "1" => {
                if let Some(storage) = log_in().await? {
                    Box::pin(home_menu(&storage)).await?;
                    break;
                }
            }
            "2" => {
                if let Some(storage) = sign_up().await? {
                    Box::pin(home_menu(&storage)).await?;
                    break;
                }
            }
            "3" => view_profile().await?,
            "4" => break,
            _ => println!("Invalid choice. Please try again."),
        }
    }
    Ok(None)
}

async fn home_menu(storage: &LocalStorage) -> Result<()> {
    loop {
        println!("\nChoose an option:");
        println!("1. View profile");
        println!("2. My profile");
        println!("3. Log out");
        println!("4. Exit");

        let choice = get_user_input("Enter your choice (1-4): ")?;

        match choice.as_str() {
            "1" => view_profile().await?,
            "2" => my_profile(storage).await?,
            "3" => {
                fs::remove_file("./local_storage.json")?;
                println!("Logged out successfully!");
                main_menu().await?;
                break;
            }
            "4" => break,
            _ => println!("Invalid choice. Please try again."),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    if let Some(storage) = LocalStorage::load() {
        println!("Welcome back, {}!", storage.username);
        home_menu(&storage).await?;
    } else {
        main_menu().await?;
    }
    Ok(())
}
