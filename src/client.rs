mod profile {
    tonic::include_proto!("profile");
}

use anyhow::{Context, Result};
use profile::profile_service_client::ProfileServiceClient as Client;

#[tokio::main]
async fn main() -> Result<()> {
    let address = "http://localhost:50051";
    Client::connect(address).await.context("Failed to connect to server")?;
    todo!();
}
