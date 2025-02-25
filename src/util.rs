use anyhow::Result;
use sea_orm::{Database, DatabaseConnection, DbErr};

#[macro_export]
macro_rules! internal {
    ($fmt:literal $(, $param:expr)*) => {{
        tracing::error!($fmt $(, $param)*);
        tonic::Status::internal(format!($fmt $(, $param)*))
    }}
}

// must be a macro to preserve tracing::error invocation location
#[macro_export]
macro_rules! error_running_query {
    () => {
        |error| {
            tracing::error!("Error running query: {error}");
            tonic::Status::internal(format!("Error running query: {error}"))
        }
    };
}

async fn connect_to_database() -> Result<DatabaseConnection, DbErr> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or("sqlite://data.db?mode=rwc".into());
    Database::connect(&database_url).await
}

lazy_static::lazy_static! {
    pub static ref conn: DatabaseConnection = futures::executor::block_on(connect_to_database())
        .expect("Failed to connection to database");
}
