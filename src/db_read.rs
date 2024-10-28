use crate::database::database::Database;
use crate::database::error::DbError;
use crate::database::execute_query::ExecuteQuery;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;
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
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<i32>,
    pub dst_port: Option<i32>,
    pub protocol: i16,
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

        const MAX_PACKET_SIZE: i64 = 1500;  // i32からi64に変更

        println!("Debug - 最終タイムスタンプ: {:?}", *last_ts);
        println!("Debug - 初回実行: {}", is_first);

        let (query, params): (_, Vec<&(dyn tokio_postgres::types::ToSql + Sync)>) = if is_first {
            // 初回実行時の処理
            println!("Debug - 初回実行、直近のパケットを取得");
            (
                "
            SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                timestamp,
                data, raw_packet
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
            // 2回目以降の処理
            match &*last_ts {
                Some(ts) => {
                    println!("Debug - タイムスタンプを使用したクエリ実行: {}", ts);
                    (
                        "
                    SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                        timestamp,
                        data, raw_packet
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
                    println!("Debug - タイムスタンプが不正な状態の為、現在時刻の5秒前から取得");
                    // タイムスタンプがない場合は現在時刻から5秒前を基準にする
                    *last_ts = Some(chrono::Utc::now() - chrono::Duration::seconds(5));
                    (
                        "
                    SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                        timestamp,
                        data, raw_packet
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
        
        println!("Debug - 実行クエリ: {}", query);
        println!("Debug - クエリパラメータ: {:?}", params);

        let rows = match db.query(query, &params).await {
            Ok(rows) => rows,
            Err(e) => {
                println!("Debug - Database error: {:?}", e);
                return Err(PacketError::from(e));
            }
        };

        println!("Debug -　{}行のデータを取得しました", rows.len());

        let mut packet_infos: Vec<PacketInfo> = Vec::new();
        let mut latest_timestamp = None;

        for row in rows {
            let timestamp: chrono::DateTime<chrono::Utc> = row.get("timestamp");
            println!("Debug - パケットのタイムスタンプを処理中: {}", timestamp);

            // 最新のタイムスタンプを更新
            if latest_timestamp.is_none() || latest_timestamp.unwrap() < timestamp {
                latest_timestamp = Some(timestamp);
            }

            let packet_info = PacketInfo {
                src_ip: row.get("src_ip"),
                dst_ip: row.get("dst_ip"),
                src_port: row.get("src_port"),
                dst_port: row.get("dst_port"),
                protocol: row.get("protocol"),
                timestamp,
                data: row.get("data"),
                raw_packet: row.get("raw_packet"),
            };

            if self.should_process_packet(&packet_info) {
                packet_infos.push(packet_info);
            }
        }

        // 最新のタイムスタンプで更新
        if let Some(ts) = latest_timestamp {
            println!("Debug - 最終タイムスタンプを更新: {}", ts);
            *last_ts = Some(ts);
        }

        if is_first {
            self.is_first_poll.store(false, Ordering::SeqCst);
            println!("Debug - 初回ポーリング完了、フラグを更新しました");
        }

        Ok(packet_infos)
    }

    pub async fn poll_and_send_packets(&self) -> Result<(), PacketError> {
        match self.poll_packets().await {
            Ok(packets) => {
                let packet_count = packets.len();
                println!("{}個のパケットを取得しました", packet_count);

                for packet in packets {
                    println!("パケット送信中: {}: {} {}",
                             packet.timestamp,
                             packet.src_ip,
                             packet.dst_ip
                    );

                    if packet.raw_packet.len() > 1500 {
                        println!("パケットサイズが大きすぎるためスキップ: {} bytes",
                                 packet.raw_packet.len()
                        );
                        self.packets_failed.fetch_add(1, Ordering::SeqCst);
                        continue;
                    }

                    let (mut tx, _) = match datalink::channel(&self.interface, Default::default()) {
                        Ok(Ethernet(tx, rx)) => (tx, rx),
                        Ok(_) => return Err(PacketError::NetworkError(
                            "未対応のチャネルタイプです".to_string()
                        )),
                        Err(e) => return Err(PacketError::NetworkError(e.to_string())),
                    };

                    match tx.send_to(&*packet.raw_packet, None) {
                        Some(Ok(_)) => {
                            self.packets_sent.fetch_add(1, Ordering::SeqCst);
                        }
                        Some(Err(e)) => {
                            println!("パケット送信に失敗しました: {}", e);
                            self.packets_failed.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        None => {
                            println!("宛先が指定されていないためスキップ");
                            self.packets_failed.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                    }
                }

                let sent = self.packets_sent.load(Ordering::SeqCst);
                let failed = self.packets_failed.load(Ordering::SeqCst);
                println!("パケット処理完了 - 成功: {}, 失敗: {}", sent, failed);

                Ok(())
            }
            Err(e) => {
                println!("Debug - ポーリングとパケット送信中のエラー: {:?}", e);
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

    println!("パケット転送を開始します: {}", my_ip);

    let poller = PacketPoller::new(my_ip, interface);
    let mut interval = interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        if let Err(e) = poller.poll_and_send_packets().await {
            eprintln!("パケット処理中にエラーが発生しました: {:?}", e);
        }
    }
}