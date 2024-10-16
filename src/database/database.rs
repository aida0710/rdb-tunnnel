use crate::database::error::DbError;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use std::sync::OnceLock;
use tokio_postgres::NoTls;

pub static DATABASE: OnceLock<Database> = OnceLock::new();

pub(crate) struct Database {
    pub pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl Database {
    pub async fn new(connection_string: &str) -> Result<Self, DbError> {
        let manager = PostgresConnectionManager::new_from_stringlike(connection_string, NoTls)?;
        let pool = Pool::builder().build(manager).await?;
        Ok(Self { pool })
    }
}