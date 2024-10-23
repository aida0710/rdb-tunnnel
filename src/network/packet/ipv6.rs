#[derive(Debug, Clone)]
pub struct IPv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: std::net::Ipv6Addr,
    pub destination: std::net::Ipv6Addr,
}

impl IPv6Header {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 40 {
            return None;
        }

        let version = (data[0] >> 4) & 0xf;
        let traffic_class = ((data[0] & 0xf) << 4) | (data[1] >> 4);
        let flow_label = u32::from_be_bytes([0, data[1] & 0xf, data[2], data[3]]);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let mut source_bytes = [0u8; 16];
        source_bytes.copy_from_slice(&data[8..24]);
        let source = std::net::Ipv6Addr::from(source_bytes);

        let mut dest_bytes = [0u8; 16];
        dest_bytes.copy_from_slice(&data[24..40]);
        let destination = std::net::Ipv6Addr::from(dest_bytes);

        Some((
            Self {
                version,
                traffic_class,
                flow_label,
                payload_length,
                next_header,
                hop_limit,
                source,
                destination,
            },
            &data[40..]
        ))
    }
}
