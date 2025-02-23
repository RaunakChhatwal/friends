use anyhow::{Context, Result};
use tonic::transport::Channel;

include!("mod.rs");

pub async fn channel() -> Result<Channel> {
    let address = format!("http://localhost:{}", std::env::var("PORT").unwrap_or("50051".into()));
    Channel::from_shared(address)?.connect().await.context("Failed to create channel")
}
