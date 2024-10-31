use crate::db_write::rdb_tunnel_packet_write;
use log::{error, info};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use std::io::{self, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn packet_analysis(interface: NetworkInterface) -> Result<(), Box<dyn std::error::Error>> {
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err("未対応のチャンネルタイプです".into()),
        Err(e) => return Err(e.into()),
    };

    info!("パケットを受信を開始しました");

    loop {
        match rx.next() {
            Ok(ethernet_packet) => {
              /*  if ethernet_packet.len() >= 14 {
                    let ethertype = u16::from_be_bytes([ethernet_packet[12], ethernet_packet[13]]);
                    //println!("Ethertype: 0x{:04x}", ethertype);

                    if ethertype == 0x0800 { // IPv4
                        if ethernet_packet.len() >= 24 { // IPv4ヘッダ(20バイト) + ICMPヘッダの開始部分
                            let protocol = ethernet_packet[23];
                            //println!("Protocol: {}", protocol);

                            if protocol == 1 { // ICMP
                                let icmp_type = ethernet_packet[34];
                                let icmp_code = ethernet_packet[35];
                                println!("protocol: {}, type: {}, code: {}", protocol, icmp_type, icmp_code);
                                info!("ICMPパケットを検出しました - Type: {}, Code: {}, src MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, dst MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        icmp_type, icmp_code,
                                        ethernet_packet[6], ethernet_packet[7], ethernet_packet[8],
                                        ethernet_packet[9], ethernet_packet[10], ethernet_packet[11],
                                        ethernet_packet[0], ethernet_packet[1], ethernet_packet[2],
                                        ethernet_packet[3], ethernet_packet[4], ethernet_packet[5]
                                    );
                            }
                        }
                    }
                }*/

                // 非同期でデータベースに書き込み
                let packet_data = ethernet_packet.to_vec();
                tokio::spawn(async move {
                    if let Err(e) = rdb_tunnel_packet_write(&packet_data).await {
                        error!("パケットの書き込みに失敗しました: {}", e);
                    }
                });
            }
            Err(e) => error!("パケットの読み取り中にエラーが発生しました: {}", e),
        }
    }
}