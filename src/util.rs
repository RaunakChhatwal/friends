use anyhow::Result;
use sea_orm::{Database, DatabaseConnection, DbErr};
use tonic::Status;

pub fn anyhow_to_status(error: anyhow::Error) -> Status {
    error.downcast().unwrap_or_else(|error| Status::internal(format!("{error:?}")))
}

async fn connect_to_database() -> Result<DatabaseConnection, DbErr> {
    let database_url = std::env::var("DATABASE_URL").unwrap_or("sqlite://data.db?mode=rwc".into());
    Database::connect(&database_url).await
}

lazy_static::lazy_static! {
    pub static ref conn: DatabaseConnection = futures::executor::block_on(connect_to_database())
        .expect("Failed to connection to database");
}
