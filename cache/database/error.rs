use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    Postgres(#[from] tokio_postgres::Error),

    #[error("Connection pool error: {0}")]
    Pool(#[from] bb8::RunError<tokio_postgres::Error>),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Database initialization error")]
    Initialization,
}