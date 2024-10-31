use crate::database::database::Database;
use crate::database::error::DbError;
use crate::database::execute_query::ExecuteQuery;
use crate::db_write::MacAddr;
use bytes::BytesMut;
use log::{debug, error, info, trace};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use postgres_types::{FromSql, IsNull, ToSql, Type};
use std::error::Error;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;

#[derive(Debug)]
pub enum PacketError {
    NetworkError(String),
    DatabaseError(DbError),
    DeviceError(String),
}

impl std::fmt::Display for PacketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketError::NetworkError(msg) => write!(f, "ネットワークエラー: {}", msg),
            PacketError::DatabaseError(e) => write!(f, "データベースエラー: {}", e),
            PacketError::DeviceError(msg) => write!(f, "デバイスエラー: {}", msg),
        }
    }
}

impl std::error::Error for PacketError {}

impl From<DbError> for PacketError {
    fn from(err: DbError) -> Self {
        PacketError::DatabaseError(err)
    }
}

#[derive(Clone)]
pub struct PacketInfo {
    pub src_mac: MacAddr,
    pub dst_mac: MacAddr,
    pub ether_type: i32,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub ip_protocol: i32,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub data: Vec<u8>,
    pub raw_packet: Vec<u8>,
}

#[derive(Clone)]
pub struct PacketPoller {
    last_timestamp: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>, // Changed from NaiveDateTime to DateTime<Utc>
    is_first_poll: Arc<AtomicBool>,
    my_ip: IpAddr,
    interface: Arc<NetworkInterface>,
    packets_sent: Arc<AtomicU64>,
    packets_failed: Arc<AtomicU64>,
}

impl PacketPoller {
    pub fn new(my_ip: IpAddr, interface: NetworkInterface) -> Self {
        Self {
            last_timestamp: Arc::new(Mutex::new(None)),
            is_first_poll: Arc::new(AtomicBool::new(true)),
            my_ip,
            interface: Arc::new(interface),
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_failed: Arc::new(AtomicU64::new(0)),
        }
    }

    fn is_broadcast_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_broadcast() ||
                    ipv4.is_multicast() ||
                    ipv4.octets() == [255, 255, 255, 255]
            }
            IpAddr::V6(ipv6) => ipv6.is_multicast(),
        }
    }

    fn should_process_packet(&self, packet: &PacketInfo) -> bool {
        let is_for_me = packet.dst_ip == self.my_ip;
        let is_broadcast = Self::is_broadcast_ip(&packet.dst_ip);

        is_for_me || is_broadcast
    }

    pub async fn poll_packets(&self) -> Result<Vec<PacketInfo>, PacketError> {
        let db = Database::get_database();
        let mut last_ts = self.last_timestamp.lock().await;
        let is_first = self.is_first_poll.load(Ordering::SeqCst);

        const MAX_PACKET_SIZE: i64 = 1500;

        let current_time = chrono::Utc::now();
        debug!("現在時刻: {}", current_time);

        let (query, params): (_, Vec<&(dyn tokio_postgres::types::ToSql + Sync)>) = if is_first {
            (
                "
            SELECT src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port, 
                ip_protocol, timestamp, data, raw_packet
            FROM packets
            WHERE length(raw_packet) <= $1::bigint
                AND (dst_ip = $2
                    OR dst_ip = '255.255.255.255'
                    OR dst_ip << '224.0.0.0/4'
                )
                AND timestamp >= NOW() - INTERVAL '30 seconds'
            ORDER BY timestamp ASC
            ",
                vec![&MAX_PACKET_SIZE, &self.my_ip]
            )
        } else {
            match &*last_ts {
                Some(ts) => {
                    (
                        "
                    SELECT src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port,
                        ip_protocol, timestamp, data, raw_packet
                    FROM packets
                    WHERE timestamp > $2
                        AND length(raw_packet) <= $1::bigint
                        AND (dst_ip = $3
                            OR dst_ip = '255.255.255.255'
                            OR dst_ip << '224.0.0.0/4'
                        )
                    ORDER BY timestamp ASC
                    ",
                        vec![&MAX_PACKET_SIZE, ts, &self.my_ip]
                    )
                }
                None => {
                    let five_seconds_ago = current_time - chrono::Duration::seconds(5);
                    *last_ts = Some(five_seconds_ago);
                    (
                        "
                    SELECT src_mac, dst_mac, ether_type, src_ip, dst_ip, src_port, dst_port,
                        ip_protocol, timestamp, data, raw_packet
                    FROM packets
                    WHERE length(raw_packet) <= $1::bigint
                        AND (dst_ip = $2
                            OR dst_ip = '255.255.255.255'
                            OR dst_ip << '224.0.0.0/4'
                        )
                        AND timestamp >= NOW() - INTERVAL '5 seconds'
                    ORDER BY timestamp ASC
                    ",
                        vec![&MAX_PACKET_SIZE, &self.my_ip]
                    )
                }
            }
        };

        debug!("実行クエリ: {}", query);
        debug!("クエリパラメータ: {:?}", params);
        debug!("クエリ実行前のタイムスタンプ: {:?}", *last_ts);

        let rows = match db.query(query, &params).await {
            Ok(rows) => rows,
            Err(e) => {
                error!("データベースクエリエラー: {:?}", e);
                debug!("エラー発生時のタイムスタンプを更新: {}", current_time);
                *last_ts = Some(current_time);
                return Err(PacketError::from(e));
            }
        };

        info!("{}行のデータを取得しました", rows.len());

        let mut packet_infos: Vec<PacketInfo> = Vec::new();
        let mut latest_timestamp = None;

        for row in rows {
            let timestamp: chrono::DateTime<chrono::Utc> = row.get("timestamp");
            info!("パケットのタイムスタンプを処理中: {}", timestamp);

            if latest_timestamp.is_none() || latest_timestamp.unwrap() < timestamp {
                latest_timestamp = Some(timestamp);
                info!("最新のタイムスタンプを更新: {}", timestamp);
            }

            let src_mac: MacAddr = row.get("src_mac");
            let dst_mac: MacAddr = row.get("dst_mac");

            debug!("Received MAC addresses - src: {}, dst: {}", src_mac, dst_mac);

            let packet_info = PacketInfo {
                src_mac,
                dst_mac,
                ether_type: row.get("ether_type"),
                src_ip: row.get("src_ip"),
                dst_ip: row.get("dst_ip"),
                src_port: row.get("src_port"),
                dst_port: row.get("dst_port"),
                ip_protocol: row.get("ip_protocol"),
                timestamp,
                data: row.get("data"),
                raw_packet: row.get("raw_packet"),
            };

            if self.should_process_packet(&packet_info) {
                trace!("パケットを処理対象に追加: {} -> {}, MAC: {} -> {}",
                    packet_info.src_ip,
                    packet_info.dst_ip,
                    packet_info.src_mac,
                    packet_info.dst_mac
                );
                packet_infos.push(packet_info);
            }
        }

        let new_timestamp = latest_timestamp.unwrap_or(current_time);
        *last_ts = Some(new_timestamp);
        info!("タイムスタンプを更新: {}", new_timestamp);
        debug!("取得したパケット数: {}", packet_infos.len());

        if is_first {
            self.is_first_poll.store(false, Ordering::SeqCst);
            info!("初回ポーリング完了、フラグを更新しました");
        }

        Ok(packet_infos)
    }

    pub async fn poll_and_send_packets(&self) -> Result<(), PacketError> {
        match self.poll_packets().await {
            Ok(packets) => {
                let packet_count = packets.len();
                debug!("{}個のパケットを取得しました", packet_count);

                for packet in packets {
                    trace!("パケット送信中: {}: {} {}",
                            packet.timestamp,
                            packet.src_ip,
                            packet.dst_ip
                        );

                    if packet.raw_packet.len() > 1500 {
                        debug!("パケットサイズが大きすぎるためスキップ: {} bytes",
                                    packet.raw_packet.len()
                        );
                        self.packets_failed.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }

                    let (mut tx, _) = match datalink::channel(&self.interface, Default::default()) {
                        Ok(Ethernet(tx, rx)) => (tx, rx),
                        Ok(_) => {
                            error!("未対応のチャネルタイプです");
                            return Err(PacketError::NetworkError("未対応のチャネルタイプです".to_string()));
                        }
                        Err(e) => return Err(PacketError::NetworkError(e.to_string())),
                    };

                    match tx.send_to(&*packet.raw_packet, None) {
                        Some(Ok(_)) => {
                            trace!("パケット送信完了: ip-prot:{} {} -> {}",
                                packet.ip_protocol,
                                packet.src_ip,
                                packet.dst_ip,
                            );
                            self.packets_sent.fetch_add(1, Ordering::SeqCst);
                        }
                        Some(Err(e)) => {
                            error!("パケット送信に失敗しました: {}", e);
                            self.packets_failed.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        None => {
                            error!("宛先が指定されていないためスキップ");
                            self.packets_failed.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                    }
                }

                let sent = self.packets_sent.load(Ordering::SeqCst);
                let failed = self.packets_failed.load(Ordering::SeqCst);
                info!("パケット処理完了 - 成功: {}, 失敗: {}", sent, failed);

                // パケット送信数をリセット
                self.packets_sent.store(0, Ordering::SeqCst);
                self.packets_failed.store(0, Ordering::SeqCst);

                Ok(())
            }
            Err(e) => {
                error!("ポーリングとパケット送信中のエラー: {:?}", e);
                Err(e)
            }
        }
    }
}

pub async fn inject_packet(interface: NetworkInterface) -> Result<(), PacketError> {
    let my_ip = interface.ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .map(|ip| ip.ip())
        .ok_or_else(|| PacketError::DeviceError("IPv4アドレスが見つかりません".to_string()))?;

    info!("パケット転送を開始します: {}", my_ip);

    let poller = PacketPoller::new(my_ip, interface);
    let mut interval = interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        if let Err(e) = poller.poll_and_send_packets().await {
            error!("パケット処理中にエラーが発生しました: {:?}", e);
        }
    }
}