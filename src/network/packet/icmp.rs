#[derive(Debug, Clone)]
pub struct ICMPHeader {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub checksum: u16,
    pub rest_of_header: u32,
}

impl ICMPHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 8 {
            return None;
        }

        let icmp_type = data[0];
        let icmp_code = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let rest_of_header = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        Some((
            Self {
                icmp_type,
                icmp_code,
                checksum,
                rest_of_header,
            },
            &data[8..]
        ))
    }
}