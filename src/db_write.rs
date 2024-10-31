use crate::database::database::Database;
use crate::packet_header::{parse_ip_header, parse_next_ip_header};
use bytes::BytesMut;
use chrono::Utc;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use log::{debug, error, info, trace};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_postgres::types::{IsNull, ToSql, Type};

// ARPプロトコル番号の定義
const ARP_PROTOCOL: u8 = 0x08;

// プロトコル定義
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    IPv4 = 0x0800,
    IPv6 = 0x86DD,
    ARP = 0x0806,
    VLAN = 0x8100,
    TCP = 6,
    UDP = 17,
    ICMP = 1,
    ICMPv6 = 58,
    DHCP = 67,
    DNS = 53,
    Unknown = 0,
}

impl Protocol {
    fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => Protocol::IPv4,
            0x86DD => Protocol::IPv6,
            0x0806 => Protocol::ARP,
            0x8100 => Protocol::VLAN,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            1 => Protocol::ICMP,
            58 => Protocol::ICMPv6,
            67 => Protocol::DHCP,
            53 => Protocol::DNS,
            _ => Protocol::Unknown,
        }
    }
}

// PostgreSQLのinet型のためのラッパー構造体
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
                out.extend_from_slice(&[2]);     // AF_INET
                out.extend_from_slice(&[32]);    // /32
                out.extend_from_slice(&[1]);     // is_cidr
                out.extend_from_slice(&[4]);     // IPv4 = 4 bytes
                out.extend_from_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                out.extend_from_slice(&[3]);     // AF_INET6
                out.extend_from_slice(&[128]);   // /128
                out.extend_from_slice(&[1]);     // is_cidr
                out.extend_from_slice(&[16]);    // IPv6 = 16 bytes
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

// データベースに保存するパケット情報の構造体
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

// パケット統計情報の収集用構造体
#[derive(Debug)]
struct PacketStats {
    total_packets: AtomicU64,
    total_bytes: AtomicU64,
    protocol_counts: Arc<Mutex<HashMap<Protocol, u64>>>,
    port_counts: Arc<Mutex<HashMap<u16, u64>>>,
    last_reset: Arc<Mutex<SystemTime>>,
}

impl PacketStats {
    fn new() -> Self {
        Self {
            total_packets: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            protocol_counts: Arc::new(Mutex::new(HashMap::new())),
            port_counts: Arc::new(Mutex::new(HashMap::new())),
            last_reset: Arc::new(Mutex::new(SystemTime::now())),
        }
    }

    // 統計情報の更新
    async fn update(&self, protocol: Protocol, size: u64, src_port: u16, dst_port: u16) {
        self.total_packets.fetch_add(1, Ordering::Relaxed);
        self.total_bytes.fetch_add(size, Ordering::Relaxed);

        let mut protocol_counts = self.protocol_counts.lock().await;
        *protocol_counts.entry(protocol).or_insert(0) += 1;

        let mut port_counts = self.port_counts.lock().await;
        if src_port > 0 {
            *port_counts.entry(src_port).or_insert(0) += 1;
        }
        if dst_port > 0 {
            *port_counts.entry(dst_port).or_insert(0) += 1;
        }
    }
}

// グローバル変数の定義
lazy_static! {
    static ref PACKET_BUFFER: Arc<Mutex<Vec<PacketData>>> = Arc::new(Mutex::new(Vec::new()));
    static ref PACKET_STATS: PacketStats = PacketStats::new();
}

// パケットライターのメインループ
pub async fn start_packet_writer() {
    info!("パケットライターを開始します");
    let mut interval = interval(Duration::from_millis(300));
    loop {
        interval.tick().await;
        // 300ミリ秒ごとにバッファをフラッシュ
        if let Err(e) = flush_packet_buffer().await {
            error!("パケットバッファのフラッシュに失敗しました: {}", e);
        }
    }
}

// バッファをデータベースに書き込む
async fn flush_packet_buffer() -> Result<(), crate::database::error::DbError> {
    let mut buffer = PACKET_BUFFER.lock().await;
    if buffer.is_empty() {
        return Ok(());
    }

    let db = Database::get_database();
    let mut client = db.pool.get().await?;
    let transaction = client.transaction().await?;

    let query = "
        INSERT INTO packets (
            src_ip, dst_ip, src_port, dst_port, protocol,
            timestamp, data, raw_packet
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ";

    let packets: Vec<PacketData> = buffer.drain(..).collect();
    for packet in &packets {
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

        if let Err(e) = transaction.execute(query, params).await {
            error!("パケットの挿入に失敗しました: {}", e);
            transaction.rollback().await?;
            PACKET_BUFFER.lock().await.extend(packets);
            return Err(crate::database::error::DbError::Postgres(e));
        }
        if packet.protocol == 1 {
            info!("ICMPパケットを挿入しました: src_ip={}, dst_ip={}", packet.src_ip.0, packet.dst_ip.0);
        }
        trace!("パケットを挿入しました: src_ip={}, dst_ip={}, protocol={}", packet.src_ip.0, packet.dst_ip.0, packet.protocol);
    }

    match transaction.commit().await {
        Ok(_) => {
            debug!("{}個のパケットを正常に挿入しました", packets.len());
            Ok(())
        }
        Err(e) => {
            error!("トランザクションのコミットに失敗しました: {}", e);
            PACKET_BUFFER.lock().await.extend(packets);
            Err(crate::database::error::DbError::Postgres(e))
        }
    }
}

// パケットの書き込みエントリーポイント
pub async fn rdb_tunnel_packet_write(ethernet_packet: &[u8]) -> Result<(), crate::database::error::DbError> {
    let packet_info = parse_and_analyze_packet(ethernet_packet).await?;

    // 統計情報の更新
    PACKET_STATS
        .update(
            Protocol::from_u16(packet_info.protocol as u16),
            ethernet_packet.len() as u64,
            packet_info.src_port as u16,
            packet_info.dst_port as u16,
        )
        .await;

    // バッファに追加
    PACKET_BUFFER.lock().await.push(packet_info);
    Ok(())
}

// イーサネットパケットの解析
// parse_and_analyze_packetの修正版
async fn parse_and_analyze_packet(ethernet_packet: &[u8]) -> Result<PacketData, crate::database::error::DbError> {
    async fn inner_parse(ethernet_packet: &[u8], depth: u8) -> Result<PacketData, crate::database::error::DbError> {
        if depth > 5 {  // 再帰の深さ制限
            return Ok(create_empty_packet_data(ethernet_packet));
        }

        let mut src_port: u16 = 0;
        let mut dst_port: u16 = 0;
        let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut protocol: u8 = 0;
        let mut payload_offset: usize = 14;

        if ethernet_packet.len() < 14 {
            return Ok(create_empty_packet_data(ethernet_packet));
        }

        let ether_type = u16::from_be_bytes([ethernet_packet[12], ethernet_packet[13]]);

        match ether_type {
            0x0800 => { // IPv4
                if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                    src_ip = ip_header.src_ip;
                    dst_ip = ip_header.dst_ip;
                    protocol = ip_header.protocol;

                    if protocol == 6 || protocol == 17 || protocol == 1 || protocol == 58 {
                        payload_offset = 14 + match ip_header.version {
                            4 => {
                                if protocol == 1 {  // ICMPv4
                                    // ICMPヘッダは8バイト
                                    let icmp_header_size = 8;
                                    20 + icmp_header_size
                                } else {
                                    20  // 通常のIPv4ヘッダサイズ
                                }
                            },
                            6 => {
                                if protocol == 58 {  // ICMPv6
                                    // ICMPv6ヘッダは8バイト
                                    let icmpv6_header_size = 8;
                                    40 + icmpv6_header_size
                                } else {
                                    40  // 通常のIPv6ヘッダサイズ
                                }
                            },
                            _ => return Ok(create_empty_packet_data(ethernet_packet)),
                        };

                        if ethernet_packet.len() > payload_offset {
                            if protocol == 6 || protocol == 17 {  // TCPまたはUDPの場合
                                let next_header = parse_next_ip_header(&ethernet_packet[payload_offset..]);
                                src_port = next_header.source_port;
                                dst_port = next_header.destination_port;
                            } else if protocol == 1 || protocol == 58 {  // ICMPまたはICMPv6の場合
                                // ICMPではポート番号の代わりにType(1バイト目)とCode(2バイト目)を使用
                                if ethernet_packet.len() >= payload_offset + 2 {
                                    src_port = ethernet_packet[payload_offset] as u16;     // ICMPタイプ
                                    dst_port = ethernet_packet[payload_offset + 1] as u16; // ICMPコード
                                }
                            }
                        }
                    }
                }
            }
            0x0806 => { // ARP
                protocol = ARP_PROTOCOL;
                if ethernet_packet.len() >= 28 {
                    let sender_ip_bytes = &ethernet_packet[28..32];
                    let target_ip_bytes = &ethernet_packet[38..42];
                    src_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        sender_ip_bytes[0], sender_ip_bytes[1],
                        sender_ip_bytes[2], sender_ip_bytes[3],
                    ));
                    dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        target_ip_bytes[0], target_ip_bytes[1],
                        target_ip_bytes[2], target_ip_bytes[3],
                    ));
                }
            }
            0x86DD => { // IPv6
                if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                    src_ip = ip_header.src_ip;
                    dst_ip = ip_header.dst_ip;
                    protocol = ip_header.protocol;
                }
            }
            0x8100 => { // VLAN
                if ethernet_packet.len() > 18 {
                    // VLAN タグをスキップして再帰呼び出し
                    let future = Box::pin(inner_parse(&ethernet_packet[4..], depth + 1));
                    return future.await;
                }
            }
            _ => {
                protocol = ether_type as u8;
            }
        }

        Ok(PacketData {
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            protocol: protocol as i16,
            timestamp: Utc::now(),
            data: ethernet_packet[payload_offset..].to_vec(),
            raw_packet: ethernet_packet.to_vec(),
        })
    }

    // 最初の呼び出し
    inner_parse(ethernet_packet, 0).await
}

// 空のパケットデータを作成
fn create_empty_packet_data(raw_packet: &[u8]) -> PacketData {
    PacketData {
        src_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        dst_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        timestamp: Utc::now(),
        data: Vec::new(),
        raw_packet: raw_packet.to_vec(),
    }
}