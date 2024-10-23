pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;
pub mod icmp;

use crate::network::packet::ethernet::EthernetHeader;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct Packet {
    pub ethernet: EthernetHeader,
    pub network: NetworkHeader,
    pub transport: Option<TransportHeader>,
    pub payload: Vec<u8>,
    pub metadata: PacketMetadata,
}

#[derive(Debug, Clone)]
pub struct PacketMetadata {
    pub timestamp: DateTime<Utc>,
    pub interface: String,
    pub length: usize,
    pub is_incoming: bool,
}

#[derive(Debug, Clone)]
pub enum NetworkHeader {
    IPv4(ipv4::IPv4Header),
    IPv6(ipv6::IPv6Header),
}

#[derive(Debug, Clone)]
pub enum TransportHeader {
    TCP(tcp::TCPHeader),
    UDP(udp::UDPHeader),
    ICMP(icmp::ICMPHeader),
}
