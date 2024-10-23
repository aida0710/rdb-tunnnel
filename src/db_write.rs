use crate::database::database::Database;
use crate::firewall::{Filter, IpFirewall, Policy};
use crate::firewall_packet::FirewallPacket;
use crate::packet_header::{parse_ip_header, parse_next_ip_header};
use bytes::BytesMut;
use chrono::Utc;
use pnet::packet::ip::IpNextHeaderProtocol;
use postgres_types::ToSql as PostgresToSql;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};
use tokio_postgres::types::{IsNull, ToSql, Type};

#[derive(Debug, Clone)]
struct InetAddr(IpAddr);

impl ToSql for InetAddr {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        match self.0 {
            IpAddr::V4(addr) => {
                // バージョン (AF_INET)
                out.extend_from_slice(&[2]);  // 2 = AF_INET
                // ネットマスク長
                out.extend_from_slice(&[32]); // /32
                // アドレスファミリー
                out.extend_from_slice(&[1]);  // 1 = is_cidr
                // アドレスバイト数
                out.extend_from_slice(&[4]);  // IPv4 = 4 bytes
                // IPアドレスのバイト
                out.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                // バージョン (AF_INET6)
                out.extend_from_slice(&[3]);  // 3 = AF_INET6
                // ネットマスク長
                out.extend_from_slice(&[128]); // /128
                // アドレスファミリー
                out.extend_from_slice(&[1]);   // 1 = is_cidr
                // アドレスバイト数
                out.extend_from_slice(&[16]);  // IPv6 = 16 bytes
                // IPアドレスのバイト
                out.extend_from_slice(&addr.octets());
            }
        }
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "inet"
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn std::error::Error + Sync + Send>> {
        self.to_sql(ty, out)
    }
}

#[derive(Debug, Clone)]
struct PacketData {
    src_ip: InetAddr,
    dst_ip: InetAddr,
    src_port: i32,
    dst_port: i32,
    protocol: i16,
    timestamp: chrono::DateTime<Utc>,
    data: Vec<u8>,
    raw_packet: Vec<u8>,
}

lazy_static::lazy_static! {
    static ref PACKET_BUFFER: Arc<Mutex<Vec<PacketData>>> = Arc::new(Mutex::new(Vec::new()));
}

pub async fn start_packet_writer() {
    println!("パケットライターを開始します");
    let mut interval = interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        println!("パケットバッファをフラッシュします");
        if let Err(e) = flush_packet_buffer().await {
            eprintln!("パケットバッファのフラッシュに失敗しました: {}", e);
        }
    }
}

async fn flush_packet_buffer() -> Result<(), crate::database::error::DbError> {
    let mut buffer = PACKET_BUFFER.lock().await;
    if buffer.is_empty() {
        println!("バッファにパケットがありません");
        return Ok(());
    }

    let db = Database::get_database();
    let mut client = db.pool.get().await?;

    let query = "INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, timestamp, data, raw_packet) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";

    let transaction = client.transaction().await?;

    let packets: Vec<PacketData> = buffer.drain(..).collect();

    for packet in &packets {
        //println!("挿入するパケット: {:?}", packet);

        let params: &[&(dyn ToSql + Sync)] = &[
            &packet.src_ip,
            &packet.dst_ip,
            &packet.src_port,
            &packet.dst_port,
            &packet.protocol,
            &packet.timestamp,
            &packet.data,
            &packet.raw_packet,
        ];

        match transaction.execute(query, params).await {
            Ok(_) => (),
            Err(e) => {
                eprintln!("パケットの挿入に失敗しました: {}", e);
                transaction.rollback().await?;
                PACKET_BUFFER.lock().await.extend(packets);
                return Err(crate::database::error::DbError::Postgres(e));
            }
        }
    }

    match transaction.commit().await {
        Ok(_) => println!("全パケットが正常に挿入されました"),
        Err(e) => {
            eprintln!("トランザクションのコミットに失敗しました: {}", e);
            PACKET_BUFFER.lock().await.extend(packets);
            return Err(crate::database::error::DbError::Postgres(e));
        }
    }

    Ok(())
}

pub async fn rdb_tunnel_packet_write(ethernet_packet: &[u8]) -> Result<(), crate::database::error::DbError> {
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let mut protocol: u8 = 0;
    let mut payload_offset: usize = 0;

    if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
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
        let _allowed = firewall.check(packet);

        let timestamp = Utc::now();
        //println!("src_ip: {}, dst_ip: {}, src_port: {}, dst_port: {}, protocol: {}, timestamp: {}",src_ip, dst_ip, src_port, dst_port, protocol, timestamp);

        let packet_data = PacketData {
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            protocol: protocol as i16,
            timestamp,
            data: ethernet_packet[payload_offset..].to_vec(),
            raw_packet: ethernet_packet.to_vec(),
        };

        PACKET_BUFFER.lock().await.push(packet_data);
    }

    Ok(())
}