use pcap::{Active, Capture};
use std::collections::HashMap;
use std::time::Duration;
use crate::packet_reassembly::ip_reassembly::IpReassembler;
use crate::packet_reassembly::packet_processor::process_packet;
use crate::packet_reassembly::tcp_stream;
use crate::packet_reassembly::tcp_stream::{TcpStream, TcpStreamKey};

pub fn packet_analysis(mut cap: Capture<Active>) -> Result<(), Box<dyn std::error::Error>> {
    let mut streams: HashMap<TcpStreamKey, TcpStream> = HashMap::new();
    let mut ip_reassembler = IpReassembler::new(Duration::from_secs(30));

    while let Ok(packet) = cap.next_packet() {
        match process_packet(&packet, &mut streams, &mut ip_reassembler) {
            Ok(_) => (),
            Err(e) => eprintln!("パケット処理中にエラーが発生しました: {}", e),
        }

        // 古いストリームの削除
        streams.retain(|_, stream| {
            stream.last_activity.elapsed() < Duration::from_secs(300) || stream.state != tcp_stream::TcpState::Closed
        });
    }

    Ok(())
}