pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

pub fn parse_udp_header(data: &[u8]) -> UDPHeader {
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    UDPHeader { src_port, dst_port }
}
