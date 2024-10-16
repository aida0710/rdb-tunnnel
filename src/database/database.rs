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

    pub async fn connect(
        host: &str,
        port: u16,
        user: &str,
        password: &str,
        database: &str,
    ) -> Result<(), DbError> {
        let connection_string = format!(
            "postgres://{}:{}@{}:{}/{}",
            user, password, host, port, database
        );
        let db = Database::new(&connection_string).await?;
        DATABASE.set(db).map_err(|_| DbError::Initialization)?;

        // 接続テスト
        let (client, connection) = tokio_postgres::connect(&connection_string, NoTls).await?;

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        // クライアントをドロップして接続を解放
        drop(client);

        Ok(())
    }

    // note: プーリングしているため、明示的な切断は不要
    /*pub async fn disconnect() -> Result<(), DbError> {
        DATABASE.get().unwrap().disconnect().await?;
        Ok(())
    }*/

    pub fn get_database() -> &'static Database {
        DATABASE.get().expect("データベースが初期化されていません")
    }
}