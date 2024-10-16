use std::net::Ipv4Addr;

pub struct IpHeader {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

pub fn parse_ip_header(data: &[u8]) -> IpHeader {
    let version = data[0] >> 4;
    let protocol = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    IpHeader {
        version,
        protocol,
        src_ip,
        dst_ip,
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

