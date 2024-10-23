use crate::network::packet::Packet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub name: String,
    pub description: String,
    pub conditions: Vec<FirewallCondition>,
    pub action: FirewallAction,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FirewallCondition {
    SourceIP(IpAddr),
    DestinationIP(IpAddr),
    SourcePort(u16),
    DestinationPort(u16),
    Protocol(u8),
    State(ConnectionState),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
}

impl FirewallRule {
    pub fn matches(&self, packet: &Packet) -> bool {
        self.conditions.iter().all(|condition| {
            match condition {
                FirewallCondition::SourceIP(ip) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            &IpAddr::V4(header.source) == ip
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                FirewallCondition::DestinationIP(ip) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            &IpAddr::V4(header.destination) == ip
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                FirewallCondition::SourcePort(port) => {
                    if let Some(transport) = &packet.transport {
                        match transport {
                            crate::network::packet::TransportHeader::TCP(header) => {
                                header.source_port == *port
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
                FirewallCondition::DestinationPort(port) => {
                    if let Some(transport) = &packet.transport {
                        match transport {
                            crate::network::packet::TransportHeader::TCP(header) => {
                                header.destination_port == *port
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
                FirewallCondition::Protocol(proto) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            header.protocol == *proto
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                FirewallCondition::State(state) => {
                    // コネクション状態の判定ロジックを実装
                    // 実際の実装では、コネクショントラッキングテーブルを参照する必要があります
                    match state {
                        ConnectionState::New => true, // 簡略化のため常にtrue
                        _ => true,
                    }
                }
            }
        })
    }
}