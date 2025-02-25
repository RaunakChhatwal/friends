use anyhow::Result;

mod auth;
mod profile;
mod util;

#[tokio::main]
async fn main() -> Result<()> {
    if let Some(storage) = util::LocalStorage::load() {
        println!("Welcome back, {}!", storage.username);
        util::home_menu(&storage).await?;
    } else {
        util::main_menu().await?;
    }
    Ok(())
}
