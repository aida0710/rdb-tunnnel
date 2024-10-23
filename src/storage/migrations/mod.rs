use crate::core::error::TunnelResult;
use tokio_postgres::Client;

pub async fn run_migrations(client: &Client) -> TunnelResult<()> {
    client
        .batch_execute(
            r#"
            -- Enable TimescaleDB extension
            CREATE EXTENSION IF NOT EXISTS timescaledb;

            -- Create packets table
            CREATE TABLE IF NOT EXISTS packets (
                id BIGSERIAL PRIMARY KEY,
                source_ip INET NOT NULL,
                destination_ip INET NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                protocol INTEGER NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                packet_data BYTEA NOT NULL,
                packet_type TEXT NOT NULL,
                interface TEXT NOT NULL,
                length INTEGER NOT NULL
            );

            -- Create hypertable
            SELECT create_hypertable('packets', 'timestamp', if_not_exists => TRUE);

            -- Create rules table
            CREATE TABLE IF NOT EXISTS rules (
                id BIGSERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                rule_type TEXT NOT NULL,
                conditions JSONB NOT NULL,
                action TEXT NOT NULL,
                priority INTEGER NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_packets_ips ON packets (source_ip, destination_ip);
            CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets (protocol);
            CREATE INDEX IF NOT EXISTS idx_rules_type ON rules (rule_type);
            "#,
        )
        .await
        .map_err(|e| crate::core::error::TunnelError::Database(e))?;

    Ok(())
}