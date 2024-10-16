use crate::host_ids::{process_packet, IpReassembler, TcpState};
use crate::vpn::rdb_vpn;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use std::time::Duration;

pub fn packet_analysis(interface: NetworkInterface) -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("未対応のチャンネルタイプです".into()),
        Err(e) => return Err(e.into()),
    };

    let mut streams = std::collections::HashMap::new();
    let mut ip_reassembler = IpReassembler::new(Duration::from_secs(30));

    loop {
        match rx.next() {
            Ok(packet) => {
                // rds-vpn
                match rdb_vpn::rdb_vpn(&packet) { _ => {} }

                // イーサネットフレームの解析
                match process_packet(&packet, &mut streams, &mut ip_reassembler) {
                    Ok(_) => (),
                    Err(e) => eprintln!("パケット処理中にエラーが発生しました: {}", e),
                }
            }
            Err(e) => eprintln!("パケットの読み取り中にエラーが発生しました: {}", e),
        }

        // 古いストリームの削除
        streams.retain(|_, stream| {
            stream.last_activity.elapsed() < Duration::from_secs(300) || stream.state != TcpState::Closed
        });
    }
}
