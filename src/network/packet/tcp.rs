#[derive(Debug, Clone)]
pub struct TCPHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: TCPFlags,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

#[derive(Debug, Clone)]
pub struct TCPFlags {
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TCPHeader {
    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 20 {
            return None;
        }

        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence_number = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgment_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0xf;
        let flags = TCPFlags {
            urg: (data[13] & 0x20) != 0,
            ack: (data[13] & 0x10) != 0,
            psh: (data[13] & 0x08) != 0,
            rst: (data[13] & 0x04) != 0,
            syn: (data[13] & 0x02) != 0,
            fin: (data[13] & 0x01) != 0,
        };
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);

        Some((
            Self {
                source_port,
                destination_port,
                sequence_number,
                acknowledgment_number,
                data_offset,
                flags,
                window_size,
                checksum,
                urgent_pointer,
            },
            &data[(data_offset as usize * 4)..]
        ))
    }
}
