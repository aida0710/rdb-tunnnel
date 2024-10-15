use crate::database::database::{Database, DATABASE};
use crate::database::error::DbError;

pub async fn connect(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    database: &str,
) -> Result<(), DbError> {
    let db = Database::new(
        &format!(
            "postgres://{}:{}@{}:{}/{}",
            user, password, host, port, database
        ),
    );
    DATABASE.set(db).map_err(|_| DbError::Initialization)?;
    DATABASE.get().unwrap().connect().await?;
    Ok(())
}

pub async fn disconnect() -> Result<(), DbError> {
    DATABASE.get().unwrap().disconnect().await?;
    Ok(())
}

pub fn get_database() -> &'static Database {
    DATABASE.get().expect("Database not initialized")
}