pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
}

pub fn parse_tcp_header(data: &[u8]) -> TcpHeader {
    TcpHeader {
        source_port: u16::from_be_bytes([data[0], data[1]]),
        destination_port: u16::from_be_bytes([data[2], data[3]]),
    }
}