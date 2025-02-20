#![feature(let_chains)]

mod auth_impl;
#[allow(warnings)]
mod entity;
mod profile_impl;
mod util;
include!("mod.rs");

use anyhow::Result;
use auth::auth_service_server::AuthServiceServer;
use auth_impl::AuthenticatedService;
use profile::profile_service_server::ProfileServiceServer;
use std::{collections::HashMap, sync::Arc};

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into())
        .add_directive("tower_http=debug".parse()?)
        .add_directive("friends=debug".parse()?)
        .add_directive("sqlx=error".parse()?)
        .add_directive("sea_orm=error".parse()?);

    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();

    tracing::info!("Starting Friends server...");

    let address = "0.0.0.0:50051".parse()?;

    let profile_service = ProfileServiceServer::new(profile_impl::ProfileService::default());
    let auth_service = AuthServiceServer::new(auth_impl::AuthService::default());

    let mut authenticated_endpoints = HashMap::new();
    authenticated_endpoints
        .insert("profile.ProfileService", profile_impl::ProfileService::authenticated_endpoints());
    let auth_layer =
        auth_impl::AuthLayer { authenticated_endpoints: Arc::new(authenticated_endpoints) };

    tonic::transport::Server::builder()
        .layer(tower::ServiceBuilder::new().layer(auth_layer).into_inner())
        .add_service(profile_service)
        .add_service(auth_service)
        .serve(address)
        .await
        .map_err(Into::into)
}
