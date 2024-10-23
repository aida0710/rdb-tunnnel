#[derive(Debug, Clone)]
pub struct UDPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UDPHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 8 {
            return None;
        }

        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        Some((
            Self {
                source_port,
                destination_port,
                length,
                checksum,
            },
            &data[8..]
        ))
    }
}