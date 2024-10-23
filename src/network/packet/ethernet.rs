#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub source: [u8; 6],
    pub destination: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn new(source: [u8; 6], destination: [u8; 6], ethertype: u16) -> Self {
        Self {
            source,
            destination,
            ethertype,
        }
    }

    pub fn parse(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.len() < 14 {
            return None;
        }

        let mut source = [0u8; 6];
        let mut destination = [0u8; 6];

        source.copy_from_slice(&data[0..6]);
        destination.copy_from_slice(&data[6..12]);
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        Some((
            Self::new(source, destination, ethertype),
            &data[14..]
        ))
    }
}