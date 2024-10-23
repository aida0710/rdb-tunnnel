use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy)]
pub struct IpHeader {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

pub fn parse_ip_header(data: &[u8]) -> Option<IpHeader> {
    let version = data[0] >> 4;
    match version {
        4 => Some(parse_ipv4_header(data)),
        6 => Some(parse_ipv6_header(data)),
        _ => None,
    }
}

fn parse_ipv4_header(data: &[u8]) -> IpHeader {
    let protocol = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    IpHeader {
        version: 4,
        protocol,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
    }
}

fn parse_ipv6_header(data: &[u8]) -> IpHeader {
    let protocol = data[6];
    let src_ip = Ipv6Addr::new(
        u16::from_be_bytes([data[8], data[9]]),
        u16::from_be_bytes([data[10], data[11]]),
        u16::from_be_bytes([data[12], data[13]]),
        u16::from_be_bytes([data[14], data[15]]),
        u16::from_be_bytes([data[16], data[17]]),
        u16::from_be_bytes([data[18], data[19]]),
        u16::from_be_bytes([data[20], data[21]]),
        u16::from_be_bytes([data[22], data[23]]),
    );
    let dst_ip = Ipv6Addr::new(
        u16::from_be_bytes([data[24], data[25]]),
        u16::from_be_bytes([data[26], data[27]]),
        u16::from_be_bytes([data[28], data[29]]),
        u16::from_be_bytes([data[30], data[31]]),
        u16::from_be_bytes([data[32], data[33]]),
        u16::from_be_bytes([data[34], data[35]]),
        u16::from_be_bytes([data[36], data[37]]),
        u16::from_be_bytes([data[38], data[39]]),
    );

    IpHeader {
        version: 6,
        protocol,
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
    }
}

pub struct NextIpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

pub fn parse_next_ip_header(data: &[u8]) -> NextIpHeader {
    NextIpHeader {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        destination_port: u16::from_be_bytes([data[2], data[3]]),
    }
}