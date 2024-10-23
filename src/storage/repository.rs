// src/storage/repository.rs
use async_trait::async_trait;
use bytes::BytesMut;
use chrono::{DateTime, TimeZone, Utc};
use tokio_postgres::{Client, NoTls, Error as PgError};
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use std::net::IpAddr;
use std::str::FromStr;
use crate::core::error::TunnelResult;
use crate::network::packet::Packet;
use crate::storage::models::packet::{StoredPacket, PacketType};
use crate::core::config::DatabaseConfig;
use tokio_postgres::types::{ToSql, Type, IsNull};
use time::OffsetDateTime;

#[async_trait]
pub trait PacketRepository: Send + Sync {
    async fn store(&self, packet: &StoredPacket) -> TunnelResult<i64>;
    async fn fetch_packets(&self, limit: i32, offset: i32) -> TunnelResult<Vec<StoredPacket>>;
    async fn fetch_for_self(&self) -> TunnelResult<Vec<StoredPacket>>;
    async fn delete_old_packets(&self, before: DateTime<Utc>) -> TunnelResult<u64>;
}

pub struct TimescaleRepository {
    pool: Pool<PostgresConnectionManager<NoTls>>,
}

impl TimescaleRepository {
    pub async fn new(config: &DatabaseConfig) -> TunnelResult<Self> {
        let manager = PostgresConnectionManager::new(
            format!(
                "host={} port={} user={} password={} dbname={}",
                config.host, config.port, config.username, config.password, config.database
            ).parse().unwrap(),
            NoTls,
        );

        let pool = Pool::builder()
            .max_size(config.max_connections)
            .build(manager)
            .await
            .map_err(|e| {
                let err: PgError = std::convert::From::from(e);
                crate::core::error::TunnelError::Database(err)
            })?;

        Ok(Self { pool })
    }

    pub async fn get_client(&self) -> TunnelResult<PooledConnection<'_, PostgresConnectionManager<NoTls>>> {
        self.pool
            .get()
            .await
            .map_err(|e| {
                let err: PgError = From::from(E);
                crate::core::error::TunnelError::Database(err)
            })
    }

    fn convert_timestamp(timestamp: &DateTime<Utc>) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(timestamp.timestamp())
            .unwrap_or_else(|_| OffsetDateTime::UNIX_EPOCH)
    }

    fn convert_error<E: std::error::Error + Send + Sync + 'static>(error: E) -> PgError {
        PgError::new(
            tokio_postgres::error::SqlState::DATA_EXCEPTION,
            error.to_string(),
        )
    }
}

#[async_trait]
impl PacketRepository for TimescaleRepository {
    async fn store(&self, packet: &StoredPacket) -> TunnelResult<i64> {
        let client = self.get_client().await?;

        let timestamp = Self::convert_timestamp(&packet.timestamp);
        let packet_type_str = serde_json::to_string(&packet.packet_type)
            .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;

        let row = client
            .query_one(
                "INSERT INTO packets (
                    source_ip, destination_ip, source_port, destination_port,
                    protocol, timestamp, packet_data, packet_type, interface, length
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                RETURNING id",
                &[
                    &packet.source_ip.to_string(),
                    &packet.destination_ip.to_string(),
                    &packet.source_port.map(|p| p as i32),
                    &packet.destination_port.map(|p| p as i32),
                    &(packet.protocol as i32),
                    &timestamp,
                    &packet.packet_data,
                    &packet_type_str,
                    &packet.interface,
                    &(packet.length as i32),
                ],
            )
            .await
            .map_err(|e| crate::core::error::TunnelError::Database(e))?;

        Ok(row.get(0))
    }

    async fn fetch_packets(&self, limit: i32, offset: i32) -> TunnelResult<Vec<StoredPacket>> {
        let client = self.get_client().await?;

        let rows = client
            .query(
                "SELECT * FROM packets ORDER BY timestamp DESC LIMIT $1 OFFSET $2",
                &[&limit, &offset],
            )
            .await
            .map_err(|e| crate::core::error::TunnelError::Database(e))?;

        let mut packets = Vec::with_capacity(rows.len());

        for row in rows {
            let timestamp: OffsetDateTime = row.get("timestamp");
            let timestamp = Utc.timestamp_opt(timestamp.unix_timestamp(), 0)
                .unwrap_or_else(|| Utc::now());

            let packet_type: String = row.get("packet_type");
            let packet_type: PacketType = serde_json::from_str(&packet_type)
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;

            let source_ip = IpAddr::from_str(&row.get::<_, String>("source_ip"))
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;
            let destination_ip = IpAddr::from_str(&row.get::<_, String>("destination_ip"))
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;

            packets.push(StoredPacket {
                id: Some(row.get("id")),
                source_ip,
                destination_ip,
                source_port: row.get::<_, Option<i32>>("source_port").map(|p| p as u16),
                destination_port: row.get::<_, Option<i32>>("destination_port").map(|p| p as u16),
                protocol: row.get::<_, i32>("protocol") as u8,
                timestamp,
                packet_data: row.get("packet_data"),
                packet_type,
                interface: row.get("interface"),
                length: row.get::<_, i32>("length") as usize,
            });
        }

        Ok(packets)
    }

    async fn fetch_for_self(&self) -> TunnelResult<Vec<StoredPacket>> {
        let client = self.get_client().await?;

        let local_addr = client
            .query_one("SELECT inet_server_addr()", &[])
            .await
            .map_err(|e| crate::core::error::TunnelError::Database(e))?
            .get::<_, String>(0);

        let rows = client
            .query(
                "SELECT * FROM packets
                 WHERE destination_ip = $1
                 ORDER BY timestamp DESC LIMIT 1000",
                &[&local_addr],
            )
            .await
            .map_err(|e| crate::core::error::TunnelError::Database(e))?;

        let mut packets = Vec::with_capacity(rows.len());

        for row in rows {
            let timestamp: OffsetDateTime = row.get("timestamp");
            let timestamp = Utc.timestamp_opt(timestamp.unix_timestamp(), 0)
                .unwrap_or_else(|| Utc::now());

            let packet_type: String = row.get("packet_type");
            let packet_type: PacketType = serde_json::from_str(&packet_type)
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;

            let source_ip = IpAddr::from_str(&row.get::<_, String>("source_ip"))
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;
            let destination_ip = IpAddr::from_str(&row.get::<_, String>("destination_ip"))
                .map_err(|e| crate::core::error::TunnelError::Database(Self::convert_error(e)))?;

            packets.push(StoredPacket {
                id: Some(row.get("id")),
                source_ip,
                destination_ip,
                source_port: row.get::<_, Option<i32>>("source_port").map(|p| p as u16),
                destination_port: row.get::<_, Option<i32>>("destination_port").map(|p| p as u16),
                protocol: row.get::<_, i32>("protocol") as u8,
                timestamp,
                packet_data: row.get("packet_data"),
                packet_type,
                interface: row.get("interface"),
                length: row.get::<_, i32>("length") as usize,
            });
        }

        Ok(packets)
    }

    async fn delete_old_packets(&self, before: DateTime<Utc>) -> TunnelResult<u64> {
        let client = self.get_client().await?;
        let timestamp = Self::convert_timestamp(&before);

        let result = client
            .execute(
                "DELETE FROM packets WHERE timestamp < $1",
                &[&timestamp],
            )
            .await
            .map_err(|e| crate::core::error::TunnelError::Database(e))?;

        Ok(result)
    }
}

impl ToSql for PacketType {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        let json = serde_json::to_string(self)?;
        json.to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <String as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        self.to_sql(ty, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_connection() {
        let config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "test".to_string(),
            password: "test".to_string(),
            database: "test_db".to_string(),
            max_connections: 5,
        };

        let repo = TimescaleRepository::new(&config).await;
        assert!(repo.is_ok(), "データベース接続に失敗しました");
    }
}