use sea_orm::{Database, DatabaseConnection};

fn connect_to_database() -> DatabaseConnection {
    let future = Database::connect(format!("sqlite://data.db?mode=rwc"));
    futures::executor::block_on(future).expect("Failed to connect to database")
}

lazy_static::lazy_static! {
    pub static ref conn: DatabaseConnection = connect_to_database();
}
