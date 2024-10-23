use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    pub id: Option<i64>,
    pub name: String,
    pub description: String,
    pub rule_type: RuleType,
    pub conditions: Vec<StoredCondition>,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    IDPS,
    Firewall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoredCondition {
    IPAddress(IpAddr),
    Port(u16),
    Protocol(u8),
    Pattern(Vec<u8>),
    Size(u32),
}