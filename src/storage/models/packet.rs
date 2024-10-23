use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPacket {
    pub id: Option<i64>,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: u8,
    pub timestamp: DateTime<Utc>,
    pub packet_data: Vec<u8>,
    pub packet_type: PacketType,
    pub interface: String,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketType {
    IPv4,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl StoredPacket {
    pub fn from_network_packet(packet: &crate::network::packet::Packet) -> Self {
        let (source_ip, destination_ip, protocol) = match &packet.network {
            crate::network::packet::NetworkHeader::IPv4(header) => {
                (IpAddr::V4(header.source),
                 IpAddr::V4(header.destination),
                 header.protocol)
            }
            crate::network::packet::NetworkHeader::IPv6(_) => {
                // IPv6の実装をここに追加
                unimplemented!()
            }
        };

        let (source_port, destination_port) = match &packet.transport {
            Some(crate::network::packet::TransportHeader::TCP(header)) => {
                (Some(header.source_port), Some(header.destination_port))
            }
            Some(crate::network::packet::TransportHeader::UDP(_)) => {
                // UDPの実装をここに追加
                (None, None)
            }
            _ => (None, None),
        };

        StoredPacket {
            id: None,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            timestamp: packet.metadata.timestamp,
            packet_data: packet.payload.clone(),
            packet_type: match protocol {
                6 => PacketType::TCP,
                17 => PacketType::UDP,
                1 => PacketType::ICMP,
                _ => PacketType::Other(protocol),
            },
            interface: packet.metadata.interface.clone(),
            length: packet.metadata.length,
        }
    }
}