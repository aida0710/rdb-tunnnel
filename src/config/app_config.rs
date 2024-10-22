use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub database: DatabaseConfig,
    pub network: NetworkConfig,
    //pub firewall: FirewallConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface: String,
    pub packet_buffer_size: usize,
    pub processing_threads: u32,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            database: DatabaseConfig {
                host: std::env::var("DB_HOST")?,
                port: std::env::var("DB_PORT")?.parse::<u16>().map_err(|_| std::env::VarError::NotPresent)?,
                username: std::env::var("DB_USER")?,
                password: std::env::var("DB_PASSWORD")?,
                database_name: std::env::var("DB_NAME")?,
            },
            network: NetworkConfig {
                interface: "".to_string(),
                packet_buffer_size: 0,
                processing_threads: 0,
            },
        })
    }

    #[cfg(test)]
    pub fn for_testing() -> Self {
        Self {
            database: DatabaseConfig {
                host: "localhost".to_string(),
                port: 5432,
                username: "test".to_string(),
                password: "test".to_string(),
                database_name: "test_db".to_string(),
            },
            network: NetworkConfig {
                interface: "".to_string(),
                packet_buffer_size: 0,
                processing_threads: 0,
            },
        }
    }
}