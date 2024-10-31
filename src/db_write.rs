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
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_postgres::types::{IsNull, ToSql, Type};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Protocol(i32);

// イーサネットプロトコル用の実装
impl Protocol {
    // EtherType Constants (IEEE 802.3)
    pub const fn ethernet(value: i32) -> Self {
        Protocol(value)
    }

    // Internet Protocol version 4
    pub const IP_V4: Protocol = Protocol::ethernet(0x0800);

    // Internet Protocol version 6
    pub const IP_V6: Protocol = Protocol::ethernet(0x86DD);

    // Address Resolution Protocol
    pub const ARP: Protocol = Protocol::ethernet(0x0806);

    // Reverse Address Resolution Protocol
    pub const RARP: Protocol = Protocol::ethernet(0x8035);

    // Internetwork Packet Exchange
    // Novell社が開発したネットワークプロトコル。現在はほぼ使用されていない
    pub const IPX: Protocol = Protocol::ethernet(0x8137);

    // Versatile Message Transaction Protocol
    // 分散システム向けの高性能トランスポートプロトコル
    pub const VMTP: Protocol = Protocol::ethernet(0x805B);

    // AppleTalk (EtherTalk)
    // Apple社が開発した独自のネットワークプロトコル。現在は非推奨
    pub const APPLE_TALK: Protocol = Protocol::ethernet(0x809B);

    // AppleTalk Address Resolution Protocol
    // AppleTalk用のアドレス解決プロトコル
    pub const AARP: Protocol = Protocol::ethernet(0x80F3);

    // Virtual LAN
    // IEEE 802.1Q。仮想LANを実現するためのプロトコル
    pub const VLAN: Protocol = Protocol::ethernet(0x8100);

    // Simple Network Management Protocol over Ethernet
    // ネットワーク機器の監視・制御用プロトコルのイーサネット実装
    pub const SNMP: Protocol = Protocol::ethernet(0x814C);

    // Network Basic Input/Output System - NetBIOS Extended User Interface
    // Windowsネットワークで使用される通信プロトコル
    pub const NET_BIOS: Protocol = Protocol::ethernet(0x8137);

    // Xpress Transfer Protocol
    // 高速データ転送用のプロトコル
    pub const XTP: Protocol = Protocol::ethernet(0x805B);

    // Multiprotocol Label Switching
    // 高性能な通信経路制御のためのプロトコル
    pub const MPLS: Protocol = Protocol::ethernet(0x8847);

    // Multiprotocol Label Switching with upstream-assigned label
    // MPLSの拡張版。上流で割り当てられたラベルを使用
    pub const MPLS_MULTI: Protocol = Protocol::ethernet(0x8848);

    // Point-to-Point Protocol over Ethernet Discovery Stage
    // PPPoEの接続確立フェーズで使用されるプロトコル
    pub const PPPOE_DISCOVERY: Protocol = Protocol::ethernet(0x8863);

    // Point-to-Point Protocol over Ethernet Session Stage
    // PPPoEのデータ転送フェーズで使用されるプロトコル
    pub const PPPOE_SESSION: Protocol = Protocol::ethernet(0x8864);

    // Ethernet Loopback Protocol
    // イーサネットのループバックテスト用プロトコル
    pub const LOOPBACK: Protocol = Protocol::ethernet(0x9000);
}

// IPプロトコル用の実装
impl Protocol {
    // IP Protocol Numbers (IANA)
    pub const fn ip(value: i32) -> Self {
        Protocol(value)
    }

    // 頻繁に使用されるIPプロトコル
    pub const ICMP: Protocol = Protocol::ip(1);
    pub const TCP: Protocol = Protocol::ip(6);
    pub const UDP: Protocol = Protocol::ip(17);
    pub const DNS: Protocol = Protocol::ip(53);
    pub const ICMP_V6: Protocol = Protocol::ip(58);
    pub const DHCP: Protocol = Protocol::ip(67);
}

// その他のユーティリティ実装
impl Protocol {
    pub const UNKNOWN: Protocol = Protocol(0);

    pub fn from_u16(value: u16) -> Self {
        Protocol(value as i32)
    }

    pub fn from_u8(value: u8) -> Self {
        Protocol(value as i32)
    }

    pub fn as_i32(&self) -> i32 {
        self.0
    }

    // イーサネットプロトコルかどうかの判定
    pub fn is_ethernet(&self) -> bool {
        self.0 >= 0x0800
    }

    // IPプロトコルかどうかの判定
    pub fn is_ip(&self) -> bool {
        self.0 > 0 && self.0 < 0x0800
    }
}

// PostgreSQL型変換の実装
impl ToSql for Protocol {
    fn to_sql(
        &self,
        _ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.0.to_sql(_ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <i32 as ToSql>::accepts(ty)
    }

    fn to_sql_checked(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.0.to_sql_checked(ty, out)
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
    ether_type: Protocol,
    src_ip: InetAddr,
    dst_ip: InetAddr,
    src_port: i32,
    dst_port: i32,
    ip_protocol: Protocol,   // IPプロトコルを保存
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

    const BATCH_SIZE: usize = 5000;

    let stmt = transaction.prepare(
        "
        INSERT INTO packets (
            src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port,
            ip_protocol, timestamp, data, raw_packet
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "
    ).await?;

    // パケットをバッチで処理
    let packets: Vec<PacketData> = buffer.drain(..).collect();
    let total_packets = packets.len();
    let mut processed = 0;
    let mut batch_count = 0;

    for chunk in packets.chunks(BATCH_SIZE) {
        let mut successful_packets = 0;

        for packet in chunk {
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

            if firewall.check(firewall_packet) {
                let params: &[&(dyn ToSql + Sync)] = &[
                    &packet.src_mac,
                    &packet.dst_mac,
                    &packet.ether_type,
                    &packet.src_ip,
                    &packet.dst_ip,
                    &packet.src_port,
                    &packet.dst_port,
                    &packet.ip_protocol,
                    &packet.timestamp,
                    &packet.data,
                    &packet.raw_packet,
                ];

                if let Ok(_) = transaction.execute(&stmt, params).await {
                    successful_packets += 1;
                }
            }
        }

        processed += chunk.len();
        batch_count += 1;
        info!("バッチ {}: {}個のパケットを処理 ({}/{})",
            batch_count, successful_packets, processed, total_packets);
    }

    match transaction.commit().await {
        Ok(_) => {
            info!("{}個のパケットを{}バッチで挿入しました", processed, batch_count);
            Ok(())
        }
        Err(e) => {
            error!("トランザクションのコミットに失敗しました: {}", e);
            PACKET_BUFFER.lock().await.extend(packets);
            Err(crate::database::error::DbError::Postgres(e))
        }
    }
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
        let mut ip_protocol = Protocol::UNKNOWN;

        let ether_type = u16::from_be_bytes([ethernet_packet[12], ethernet_packet[13]]);
        let ether_type_protocol = Protocol::from_u16(ether_type);

        match ether_type {
            0x0800 => { // IPv4
                if ethernet_packet.len() > 23 {
                    if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                        src_ip = ip_header.src_ip;
                        dst_ip = ip_header.dst_ip;
                        // IPv4ヘッダーのプロトコルフィールドから取得
                        ip_protocol = Protocol::ip(ethernet_packet[23] as i32);
                    }
                }
            }
            0x86DD => { // IPv6
                if ethernet_packet.len() > 20 {
                    if let Some(ip_header) = parse_ip_header(&ethernet_packet[14..]) {
                        src_ip = ip_header.src_ip;
                        dst_ip = ip_header.dst_ip;
                        // IPv6ヘッダーの次ヘッダフィールドから取得
                        ip_protocol = Protocol::ip(ethernet_packet[20] as i32);
                    }
                }
            }
            0x8100 => { // VLAN
                if ethernet_packet.len() > 18 {
                    // VLAN タグをスキップして再帰呼び出し
                    let future = Box::pin(inner_parse(&ethernet_packet[4..], depth + 1));
                    return future.await;
                }
            }
            0x8035 | 0x8847 | 0x8848 | 0x8863 | 0x8864 => {
                ip_protocol = Protocol::UNKNOWN;
            }
            _ => {
                return Ok(create_empty_packet_data(ethernet_packet));
            }
        }

        Ok(PacketData {
            src_mac,
            dst_mac,
            ether_type: ether_type_protocol,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            ip_protocol,
            timestamp: Utc::now(),
            data: ethernet_packet[payload_offset..].to_vec(),
            raw_packet: ethernet_packet.to_vec(),
        })
    }

    // 最初の呼び出し
    inner_parse(ethernet_packet, 0).await
}

// パケットの書き込みエントリーポイント
pub async fn rdb_tunnel_packet_write(ethernet_packet: &[u8]) -> Result<(), crate::database::error::DbError> {
    // イーサネットヘッダーからMACアドレスを取得（最低14バイトあることは確認）
    if ethernet_packet.len() < 14 {
        error!("Invalid ethernet packet length");
        return Ok(());
    }

    match parse_and_analyze_packet(ethernet_packet).await {
        Ok(packet_data) => {
            // バッファに追加
            PACKET_BUFFER.lock().await.push(packet_data);
            Ok(())
        }
        Err(e) => {
            error!("パケット解析エラー: {}", e);
            Err(e)
        }
    }
}

// 空のパケットデータを作成
fn create_empty_packet_data(raw_packet: &[u8]) -> PacketData {
    PacketData {
        src_mac: MacAddr([0; 6]),
        dst_mac: MacAddr([0; 6]),
        ether_type: Protocol::UNKNOWN,
        src_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        dst_ip: InetAddr(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0))),
        src_port: 0,
        dst_port: 0,
        ip_protocol: Protocol::UNKNOWN,
        timestamp: Utc::now(),
        data: Vec::new(),
        raw_packet: raw_packet.to_vec(),
    }
}