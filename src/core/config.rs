use crate::core::TunnelError;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Configuration {
    pub network: NetworkConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub mtu: u16,
    pub buffer_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub idps_enabled: bool,
    pub firewall_enabled: bool,
    pub max_packet_size: usize,
    pub rate_limit: u32,
}

impl Configuration {
    pub fn from_env() -> Result<Self, TunnelError> {
        dotenv::dotenv().ok();

        Ok(Configuration {
            network: NetworkConfig {
                interface: std::env::var("NETWORK_INTERFACE")
                    .unwrap_or_else(|_| "eth0".to_string()),
                listen_addr: std::env::var("LISTEN_ADDR")
                    .unwrap_or_else(|_| "0.0.0.0".to_string())
                    .parse()
                    .map_err(|e| TunnelError::Config(format!("無効なリスニングアドレス: {}", e)))?,
                listen_port: std::env::var("LISTEN_PORT")
                    .unwrap_or_else(|_| "8000".to_string())
                    .parse()
                    .map_err(|e| TunnelError::Config(format!("無効なポート番号: {}", e)))?,
                mtu: 1500,
                buffer_size: 65535,
            },
            database: DatabaseConfig {
                host: std::env::var("DB_HOST")
                    .map_err(|_| TunnelError::Config("DB_HOSTが設定されていません".to_string()))?,
                port: std::env::var("DB_PORT")
                    .unwrap_or_else(|_| "5432".to_string())
                    .parse()
                    .map_err(|e| TunnelError::Config(format!("無効なDBポート: {}", e)))?,
                username: std::env::var("DB_USER")
                    .map_err(|_| TunnelError::Config("DB_USERが設定されていません".to_string()))?,
                password: std::env::var("DB_PASSWORD")
                    .map_err(|_| TunnelError::Config("DB_PASSWORDが設定されていません".to_string()))?,
                database: std::env::var("DB_NAME")
                    .map_err(|_| TunnelError::Config("DB_NAMEが設定されていません".to_string()))?,
                max_connections: 10,
            },
            security: SecurityConfig {
                idps_enabled: true,
                firewall_enabled: true,
                max_packet_size: 65535,
                rate_limit: 1000,
            },
        })
    }
}