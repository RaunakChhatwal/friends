use sea_orm::{Database, DatabaseConnection};

#[macro_export]
macro_rules! internal {
    ($fmt:literal $(, $param:expr)*) => {
        tonic::Status::internal(format!($fmt $(, $param)*))
    }
}

fn connect_to_database() -> DatabaseConnection {
    let future = Database::connect(format!("sqlite://data.db?mode=rwc"));
    futures::executor::block_on(future).expect("Failed to connect to database")
}

lazy_static::lazy_static! {
    pub static ref conn: DatabaseConnection = connect_to_database();
}

pub fn to_internal_db_err(_error: impl std::error::Error) -> tonic::Status {
    tonic::Status::internal("Database error") // keep internal error intentionally vague
}
