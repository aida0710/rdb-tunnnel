use std::net::IpAddr;

#[derive(Clone, Copy)]
pub struct FirewallPacket {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_version: u8,
}

impl FirewallPacket {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, ip_version: u8) -> FirewallPacket {
        FirewallPacket {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            ip_version,
        }
    }
}