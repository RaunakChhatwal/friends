use crate::auth;
use crate::profile;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tonic::Status;

// UI helper functions

pub fn format_error(status: Status) -> String {
    format!("{}: {}", status.code(), status.message())
}

pub fn get_user_input(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// Storage functionality

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalStorage {
    pub username: String,
    pub login_token: String,
}

impl LocalStorage {
    pub fn load() -> Option<Self> {
        let path = Path::new("./local_storage.json");
        if !path.exists() {
            return None;
        }

        fs::read_to_string(path).ok().and_then(|data| serde_json::from_str(&data).ok())
    }

    pub fn store(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write("./local_storage.json", json)?;
        Ok(())
    }

    pub fn remove() -> Result<()> {
        fs::remove_file("./local_storage.json")?;
        Ok(())
    }
}

// Menu functionality

pub async fn main_menu() -> Result<Option<String>> {
    loop {
        println!("\nChoose an option:");
        println!("1. Login");
        println!("2. Sign up");
        println!("3. View profile");
        println!("4. Exit");

        let choice = get_user_input("Enter your choice (1-4): ")?;

        match choice.as_str() {
            "1" => {
                if let Some(storage) = auth::log_in().await? {
                    Box::pin(home_menu(&storage)).await?;
                    break;
                }
            }
            "2" => {
                if let Some(storage) = auth::sign_up().await? {
                    Box::pin(home_menu(&storage)).await?;
                    break;
                }
            }
            "3" => profile::view_profile().await?,
            "4" => break,
            _ => println!("Invalid choice. Please try again."),
        }
    }
    Ok(None)
}

pub async fn home_menu(storage: &LocalStorage) -> Result<()> {
    loop {
        println!("\nChoose an option:");
        println!("1. View profile");
        println!("2. My profile");
        println!("3. Log out");
        println!("4. Exit");

        let choice = get_user_input("Enter your choice (1-4): ")?;

        match choice.as_str() {
            "1" => profile::view_profile().await?,
            "2" => profile::my_profile(storage).await?,
            "3" => {
                LocalStorage::remove()?;
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
