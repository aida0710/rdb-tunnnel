#[derive(Debug, Clone)]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: std::net::Ipv4Addr,
    pub destination: std::net::Ipv4Addr,
}

impl IPv4Header {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0xf;
        let ihl = data[0] & 0xf;
        let dscp = data[1] >> 2;
        let ecn = data[1] & 0x3;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = (data[6] >> 5) & 0x7;
        let fragment_offset = u16::from_be_bytes([data[6] & 0x1f, data[7]]);
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let destination = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        Some((
            Self {
                version,
                ihl,
                dscp,
                ecn,
                total_length,
                identification,
                flags,
                fragment_offset,
                ttl,
                protocol,
                checksum,
                source,
                destination,
            },
            &data[(ihl as usize * 4)..]
        ))
    }
}
