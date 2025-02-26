#![feature(let_chains)]

mod auth_impl;
#[allow(warnings)]
mod entity;
mod middleware;
mod profile_impl;
mod util;
include!("lib.rs");

use anyhow::Result;
use tracing_appender::rolling::{RollingFileAppender, Rotation};

macro_rules! add_services {
    ($server:expr, [$((
        $package:ident :: $service_server:ident :: $ServiceServer:ident,
        $service_impl:ident :: $Service:ident
    )),*]) => {{
        let mut authenticated_endpoints = ::std::collections::HashMap::new();
        $(
            let endpoints = <$service_impl::$Service as middleware::AuthenticatedEndpoints>
                ::authenticated_endpoints();
            if !endpoints.is_empty() {
                authenticated_endpoints.insert($package::$service_server::SERVICE_NAME, endpoints);
            }
        )*

        let auth_layer = middleware::AuthLayer
            { authenticated_endpoints: ::std::sync::Arc::new(authenticated_endpoints) };
        let mut server = $server
            .layer(tower::ServiceBuilder::new()
                .layer(middleware::ErrorLoggingLayer::default())
                .layer(auth_layer)
                .into_inner());

        $(
            let service =
                $package::$service_server::$ServiceServer::new($service_impl::$Service::default());
            let server = server.add_service(service);
        )*

        server
    }};
}

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into())
        .add_directive("tower_http=debug".parse()?)
        .add_directive("friends=debug".parse()?)
        .add_directive("sqlx=error".parse()?)
        .add_directive("sea_orm=error".parse()?);

    // Initialize the tracing subscriber with both console and file outputs
    let builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_file(true)
        .with_line_number(true)
        .with_target(true);

    if let Ok(log_dir) = std::env::var("LOG_DIR") {
        let file_appender = RollingFileAppender::new(Rotation::NEVER, log_dir, "logs");
        builder.with_writer(file_appender).init();
    } else {
        builder.init();
    }

    tracing::info!("Starting server...");

    let server = add_services!(
        tonic::transport::Server::builder(),
        [
            (auth::auth_service_server::AuthServiceServer, auth_impl::AuthService),
            (profile::profile_service_server::ProfileServiceServer, profile_impl::ProfileService)
        ]
    );

    let address = format!("0.0.0.0:{}", std::env::var("PORT").unwrap_or("50051".into())).parse()?;
    server.serve(address).await.map_err(Into::into)
}
