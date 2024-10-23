use crate::database::database::Database;
use chrono::Utc;
use pnet::packet::ip::IpNextHeaderProtocol;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tokio_postgres::Transaction;
use crate::firewall::{Filter, IpFirewall, Policy};
use crate::firewall_packet::FirewallPacket;
use crate::packet_header::{parse_ip_header, parse_next_ip_header};

struct PacketData {
    src_ip: String,
    dst_ip: String,
    src_port: i32,
    dst_port: i32,
    protocol: i16,
    timestamp: String,
    data: Vec<u8>,
    raw_packet: Vec<u8>,
}

lazy_static::lazy_static! {
    static ref PACKET_BUFFER: Arc<Mutex<Vec<PacketData>>> = Arc::new(Mutex::new(Vec::new()));
}

pub async fn start_packet_writer() {
    let mut interval = interval(Duration::from_millis(500));
    loop {
        interval.tick().await;
        flush_packet_buffer().await.expect("パケットバッファのフラッシュに失敗しました");
    }
}

async fn flush_packet_buffer() -> Result<(), crate::database::error::DbError> {
    let mut buffer = PACKET_BUFFER.lock().await;
    if buffer.is_empty() {
        return Ok(());
    }

    let db = Database::get_database();
    let mut client = db.pool.get().await?;
    let transaction: Transaction<'_> = client.transaction().await?;

    let query = "INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, timestamp, data, raw_packet) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";

    for packet in buffer.drain(..) {
        let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
            &packet.src_ip,
            &packet.dst_ip,
            &packet.src_port,
            &packet.dst_port,
            &packet.protocol,
            &packet.timestamp,
            &packet.data,
            &packet.raw_packet,
        ];
        transaction.execute(query, params).await?;
    }

    transaction.commit().await?;
    println!("バッチでパケット情報をデータベースに正常に挿入しました");
    Ok(())
}

pub async fn rdb_tunnel_packet_write(ethernet_packet: &[u8]) -> Result<(), crate::database::error::DbError> {
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let mut protocol: u8 = 0;
    let mut payload_offset: usize = 0;

    if let Some(ip_header) = parse_ip_header(&ethernet_packet) {
        src_ip = ip_header.src_ip;
        dst_ip = ip_header.dst_ip;
        protocol = ip_header.protocol;

        if protocol == 6 || protocol == 17 {
            payload_offset = match ip_header.version {
                4 => 20,
                6 => 40,
                _ => return Ok(()),
            };

            if ethernet_packet.len() > payload_offset {
                let next_ip_header = parse_next_ip_header(&ethernet_packet[payload_offset..]);
                src_port = next_ip_header.source_port;
                dst_port = next_ip_header.destination_port;
            }
        }

        let mut firewall = IpFirewall::new(Policy::Blacklist);
        firewall.add_rule(Filter::Port(13454), 1);
        let packet = FirewallPacket::new(src_ip, dst_ip, src_port, dst_port, ip_header.version, IpNextHeaderProtocol(protocol));
        let allowed = firewall.check(packet);
        println!("ブラックリスト - パケット許可: {}", allowed);

        let packet_data = PacketData {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            protocol: protocol as i16,
            timestamp: Utc::now().to_string(),
            data: ethernet_packet[payload_offset..].to_vec(),
            raw_packet: ethernet_packet.to_vec(),
        };

        PACKET_BUFFER.lock().await.push(packet_data);
    } else {
        println!("IPヘッダーのパースに失敗しました");
    }

    Ok(())
}