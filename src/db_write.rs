use crate::database::database::Database;
use crate::firewall::{Filter, IpFirewall, Policy};
use crate::firewall_packet::FirewallPacket;
use crate::packet_header::{parse_ip_header, parse_next_ip_header};
use bytes::BytesMut;
use chrono::Utc;
use lazy_static::lazy_static;
use log::{debug, error, info, trace};
use pnet::packet::ip::IpNextHeaderProtocol;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use postgres_types::FromSql;
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



#[derive(Debug, Clone)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mac_string = self.0.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":");
        write!(f, "{}", mac_string)
    }
}

impl ToSql for MacAddr {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        out.extend_from_slice(&self.0);
        Ok(IsNull::No)
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "macaddr"
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.to_sql(ty, out)
    }
}

impl<'a> FromSql<'a> for MacAddr {
    fn from_sql(_ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        if raw.len() != 6 {
            error!("MACアドレスの長さが不正です");
            return Err("Invalid MAC address length".into());
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(raw);
        Ok(MacAddr(addr))
    }

    fn accepts(ty: &Type) -> bool {
        ty.name() == "macaddr"
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
    src_mac: MacAddr,
    dst_mac: MacAddr,
    src_ip: InetAddr,
    dst_ip: InetAddr,
    src_port: i32,
    dst_port: i32,
    protocol: u8,
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
    info!("バッファに{}個のパケットがあります", buffer.len());
    if buffer.is_empty() {
        info!("バッファが空の為、データベースへの書き込みをスキップしました");
        return Ok(());
    }

    // firewallの設定
    let mut firewall = IpFirewall::new(Policy::Blacklist);
    firewall.add_rule(Filter::Port(13432), 90);
    firewall.add_rule(Filter::Port(2222), 80);

    let db = Database::get_database();
    let mut client = db.pool.get().await?;
    let transaction = client.transaction().await?;

    let query = "
        INSERT INTO packets (
            src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
            protocol, timestamp, data, raw_packet
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    ";
    let packets: Vec<PacketData> = buffer.drain(..).collect();
    for packet in &packets {
        // パケットデータからFirewallPacketを作成
        let firewall_packet = FirewallPacket::new(
            packet.src_ip.0,
            packet.dst_ip.0,
            packet.src_port as u16,
            packet.dst_port as u16,
            match packet.src_ip.0 {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
        );

        // firewallでチェック
        if !firewall.check(firewall_packet) {
            trace!("Firewall: パケットをブロックしました - src_ip: {}, dst_ip: {}, src_port: {}, dst_port: {}",
                packet.src_ip.0, packet.dst_ip.0, packet.src_port, packet.dst_port);
            continue;
        }

        let params: &[&(dyn ToSql + Sync)] = &[
            &packet.src_mac,
            &packet.dst_mac,
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
        trace!("パケットを挿入しました: src_ip={}, dst_ip={}, protocol={}", packet.src_ip.0, packet.dst_ip.0, packet.protocol);
    }

    match transaction.commit().await {
        Ok(_) => {
            info!("{}個のパケットを正常に挿入しました", packets.len());
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
    let timestamp = Utc::now();

    // イーサネットヘッダーからMACアドレスを取得（最低14バイトあることは確認）
    if ethernet_packet.len() < 14 {
        error!("Invalid ethernet packet length");
        return Ok(());
    }

    let src_mac = MacAddr([
        ethernet_packet[6], ethernet_packet[7], ethernet_packet[8],
        ethernet_packet[9], ethernet_packet[10], ethernet_packet[11]
    ]);
    let dst_mac = MacAddr([
        ethernet_packet[0], ethernet_packet[1], ethernet_packet[2],
        ethernet_packet[3], ethernet_packet[4], ethernet_packet[5]
    ]);

    let packet_data = PacketData {
        src_mac,
        dst_mac,
        src_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))), // ダミー値
        dst_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))), // ダミー値
        src_port: 0,    // 不要な情報
        dst_port: 0,    // 不要な情報
        protocol: 0,    // 不要な情報
        timestamp,
        data: Vec::new(), // 不要な情報
        raw_packet: ethernet_packet.to_vec(),  // 生のパケットデータ
    };

    // バッファに追加
    PACKET_BUFFER.lock().await.push(packet_data);

    Ok(())
}

// イーサネットパケットの解析
async fn parse_and_analyze_packet(ethernet_packet: &[u8]) -> Result<PacketData, crate::database::error::DbError> {
    async fn inner_parse(ethernet_packet: &[u8], depth: u8) -> Result<PacketData, crate::database::error::DbError> {
        if depth > 5 || ethernet_packet.len() < 14 {
            return Ok(create_empty_packet_data(ethernet_packet));
        }

        let dst_mac = MacAddr([
            ethernet_packet[0], ethernet_packet[1], ethernet_packet[2],
            ethernet_packet[3], ethernet_packet[4], ethernet_packet[5]
        ]);
        let src_mac = MacAddr([
            ethernet_packet[6], ethernet_packet[7], ethernet_packet[8],
            ethernet_packet[9], ethernet_packet[10], ethernet_packet[11]
        ]);

        let mut src_port: u16 = 0;
        let mut dst_port: u16 = 0;
        let mut src_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        let mut dst_ip = IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
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
                }
            }
            0x0806 => { // ARP
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
                return Ok(create_empty_packet_data(ethernet_packet));
            }
        }

        Ok(PacketData {
            src_mac,
            dst_mac,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            protocol: ethernet_packet[23],
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
        src_mac: MacAddr([0; 6]),
        dst_mac: MacAddr([0; 6]),
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