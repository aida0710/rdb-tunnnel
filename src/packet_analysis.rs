use pcap::{Active, Capture};
use std::collections::HashMap;
use std::time::Duration;
use crate::host_ids::{process_packet, IpReassembler, TcpStream, TcpStreamKey};
use crate::host_ids::TcpState;

pub fn packet_analysis(mut cap: Capture<Active>) -> Result<(), Box<dyn std::error::Error>> {
    let mut streams: HashMap<TcpStreamKey, TcpStream> = HashMap::new();
    let mut ip_reassembler: IpReassembler = IpReassembler::new(Duration::from_secs(30));

    while let Ok(packet) = cap.next_packet() {
        // VPN処理


        // IDS処理
        match process_packet(&packet, &mut streams, &mut ip_reassembler) {
            Ok(_) => (),
            Err(e) => eprintln!("パケット処理中にエラーが発生しました: {}", e),
        }

        // 古いストリームの削除
        streams.retain(|_, stream| {
            stream.last_activity.elapsed() < Duration::from_secs(300) || stream.state != TcpState::Closed
        });
    }

    Ok(())
}