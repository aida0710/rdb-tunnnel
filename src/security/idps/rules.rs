use crate::network::packet::Packet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub action: RuleAction,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    IpSource(IpAddr),
    IpDestination(IpAddr),
    PortSource(u16),
    PortDestination(u16),
    Protocol(u8),
    PayloadPattern(Vec<u8>),
    PacketSize(RangeCondition),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeCondition {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

impl Rule {
    pub fn matches(&self, packet: &Packet) -> bool {
        self.conditions.iter().all(|condition| {
            match condition {
                RuleCondition::IpSource(ip) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            &IpAddr::V4(header.source) == ip
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                RuleCondition::IpDestination(ip) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            &IpAddr::V4(header.destination) == ip
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                RuleCondition::PortSource(port) => {
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
                RuleCondition::PortDestination(port) => {
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
                RuleCondition::Protocol(proto) => {
                    match &packet.network {
                        crate::network::packet::NetworkHeader::IPv4(header) => {
                            header.protocol == *proto
                        }
                        crate::network::packet::NetworkHeader::IPv6(_) => false,
                    }
                }
                RuleCondition::PayloadPattern(pattern) => {
                    packet.payload.windows(pattern.len()).any(|window| window == pattern)
                }
                RuleCondition::PacketSize(range) => {
                    let size = packet.payload.len();
                    match (range.min, range.max) {
                        (Some(min), Some(max)) => size >= min && size <= max,
                        (Some(min), None) => size >= min,
                        (None, Some(max)) => size <= max,
                        (None, None) => true,
                    }
                }
            }
        })
    }
}

pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }

    pub fn remove_rule(&mut self, name: &str) {
        self.rules.retain(|r| r.name != name);
    }

    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }
}