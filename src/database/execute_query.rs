use crate::database::database::Database;
use crate::database::error::DbError;
use async_trait::async_trait;

#[async_trait]
pub trait ExecuteQuery {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DbError>;
}

#[async_trait]
impl ExecuteQuery for Database {
    async fn execute(&self, query: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> Result<u64, DbError> {
        let client = self.pool.get().await?;
        let stmt = client.prepare(query).await?;
        let result = client.execute(&stmt, params).await?;
        Ok(result)
    }
}