#![feature(let_chains)]

mod auth_impl;
#[allow(warnings)]
mod entity;
mod profile_impl;
mod util;
include!("mod.rs");

use anyhow::Result;

macro_rules! add_services {
    ($server:ident, [$((
        $package:ident :: $service_server:ident :: $ServiceServer:ident,
        $service_impl:ident :: $Service:ident
    )),*]) => {{
        let mut authenticated_endpoints = ::std::collections::HashMap::new();
        $(
            let endpoints = <$service_impl::$Service as auth_impl::AuthenticatedEndpoints>
                ::authenticated_endpoints();
            if !endpoints.is_empty() {
                authenticated_endpoints.insert($package::$service_server::SERVICE_NAME, endpoints);
            }
        )*

        let auth_layer = auth_impl::AuthLayer
            { authenticated_endpoints: ::std::sync::Arc::new(authenticated_endpoints) };
        let mut server = $server.layer(tower::ServiceBuilder::new().layer(auth_layer).into_inner());

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

    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .init();

    tracing::info!("Starting Friends server...");

    let address = "0.0.0.0:50051".parse()?;

    let server = tonic::transport::Server::builder();
    let server = add_services!(
        server,
        [
            (auth::auth_service_server::AuthServiceServer, auth_impl::AuthService),
            (profile::profile_service_server::ProfileServiceServer, profile_impl::ProfileService)
        ]
    );

    server.serve(address).await.map_err(Into::into)
}
