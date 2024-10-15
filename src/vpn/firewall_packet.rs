use std::net::IpAddr;
use pnet::packet::ip::IpNextHeaderProtocol;

pub struct FirewallPacket {
    pub ip_address: IpAddr,
    pub port: u16,
    pub ip_version: u8,
    pub next_header_protocol: IpNextHeaderProtocol,
}

impl FirewallPacket {
    pub fn new(ip_address: IpAddr, port: u16, ip_version: u8, next_header_protocol: IpNextHeaderProtocol) -> Self {
        FirewallPacket {
            ip_address,
            port,
            ip_version,
            next_header_protocol,
        }
    }
}