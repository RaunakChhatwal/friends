use crate::util::{LocalStorage, format_error, get_user_input};
use anyhow::Result;
use friends::auth::{LogInRequest, SignUpRequest, auth_service_client::AuthServiceClient};
use friends::profile;
use tonic::transport::Channel;

pub async fn create_channel() -> Result<Channel> {
    tonic::transport::Channel::from_static("http://0.0.0.0:50051")
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create channel: {}", e))
}

pub async fn log_in() -> Result<Option<LocalStorage>> {
    let mut auth_client = AuthServiceClient::new(create_channel().await?);

    let username = get_user_input("Enter username: ")?;
    let password = get_user_input("Enter password: ")?;

    let login_request = LogInRequest { username: username.clone(), password };
    match auth_client.log_in(login_request).await {
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

pub async fn sign_up() -> Result<Option<LocalStorage>> {
    let mut auth_client = AuthServiceClient::new(create_channel().await?);
    let mut profile_client =
        profile::profile_service_client::ProfileServiceClient::new(create_channel().await?);

    let username = loop {
        let username = get_user_input("Choose a username: ")?;

        // Check if username exists
        let check_request = tonic::Request::new(profile::User { username: username.clone() });
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
        match chrono::NaiveDate::parse_from_str(&input, "%Y-%m-%d") {
            Ok(date) => {
                let (y, m, d) = (
                    date.format("%Y").to_string().parse::<u32>().unwrap(),
                    date.format("%m").to_string().parse::<u32>().unwrap(),
                    date.format("%d").to_string().parse::<u32>().unwrap(),
                );
                break Some(profile::Date { year: y, month: m, day: d });
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
