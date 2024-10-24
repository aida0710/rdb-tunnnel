use crate::database::database::Database;
use crate::database::error::DbError;
use crate::database::execute_query::ExecuteQuery;
use crate::select_device::select_device;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::interval;

// カスタムエラー型の定義
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
    pub timestamp: String,
    pub data: Vec<u8>,
    pub raw_packet: Vec<u8>,
}

#[derive(Clone)]
pub struct PacketPoller {
    last_timestamp: Arc<Mutex<Option<String>>>,
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

        let query = match &*last_ts {
            Some(_ts) => "
               SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                   to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS.US') as timestamp,
                   data, raw_packet
               FROM packets
               WHERE timestamp > $1::timestamp
                   AND (dst_ip = $2
                       OR dst_ip = '255.255.255.255'
                       OR dst_ip << '224.0.0.0/4'
                   )
               ORDER BY timestamp ASC
               ",
            None => "
               SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                   to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS.US') as timestamp,
                   data, raw_packet
               FROM packets
               WHERE dst_ip = $1
                   OR dst_ip = '255.255.255.255'
                   OR dst_ip << '224.0.0.0/4'
               ORDER BY timestamp ASC
               ",
        };

        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = match &*last_ts {
            Some(ts) => vec![ts, &self.my_ip],
            None => vec![&self.my_ip],
        };

        let rows = db.query(query, &params).await.map_err(PacketError::from)?;

        let packet_infos: Vec<PacketInfo> = rows
            .into_iter()
            .map(|row| PacketInfo {
                src_ip: row.get("src_ip"),
                dst_ip: row.get("dst_ip"),
                src_port: row.get("src_port"),
                dst_port: row.get("dst_port"),
                protocol: row.get("protocol"),
                timestamp: row.get("timestamp"),
                data: row.get("data"),
                raw_packet: row.get("raw_packet"),
            })
            .filter(|packet| self.should_process_packet(packet))
            .collect();

        if let Some(last_packet) = packet_infos.last() {
            *last_ts = Some(last_packet.timestamp.clone());
        }

        Ok(packet_infos)
    }

    async fn send_raw_packet_with_retry(
        &self,
        raw_packet: &[u8],
        max_retries: u32,
        retry_delay: Duration,
    ) -> Result<(), PacketError> {
        let mut retries = 0;
        let mut last_error = None;

        while retries < max_retries {
            match self.send_raw_packet(raw_packet).await {
                Ok(_) => {
                    self.packets_sent.fetch_add(1, Ordering::Relaxed);
                    if retries > 0 {
                        println!("パケット送信成功 ({}回目の再試行で成功)", retries + 1);
                    }
                    return Ok(());
                }
                Err(e) => {
                    last_error = Some(e);
                    if retries < max_retries - 1 {
                        eprintln!("送信失敗（再試行 {}/{}）", retries + 1, max_retries);
                        retries += 1;
                        tokio::time::sleep(retry_delay).await;
                    }
                }
            }
        }

        self.packets_failed.fetch_add(1, Ordering::Relaxed);
        Err(last_error.unwrap_or(PacketError::NetworkError("不明なエラー".to_string())))
    }

    async fn send_raw_packet(&self, raw_packet: &[u8]) -> Result<(), PacketError> {
        let (mut tx, _) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(PacketError::NetworkError("未対応のチャネルタイプです".to_string())),
            Err(e) => return Err(PacketError::NetworkError(e.to_string())),
        };

        match tx.send_to(raw_packet, None) {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(PacketError::NetworkError(format!("パケット送信に失敗しました: {}", e))),
            None => Err(PacketError::NetworkError("宛先が指定されていません".to_string())),
        }
    }

    pub async fn poll_and_send_packets(&self) -> Result<(), PacketError> {
        match self.poll_packets().await {
            Ok(packets) => {
                let packet_count = packets.len();
                if packet_count > 0 {
                    println!("{}個のパケットを取得しました", packet_count);
                }

                for packet in packets {
                    println!("パケット処理中: {} -> {}", packet.src_ip, packet.dst_ip);

                    match self.send_raw_packet_with_retry(
                        &packet.raw_packet,
                        3,
                        Duration::from_millis(100),
                    ).await {
                        Ok(_) => {
                            let (sent, failed) = self.get_stats();
                            println!(
                                "パケット送信成功: {} -> {} (成功: {}, 失敗: {})",
                                packet.src_ip,
                                packet.dst_ip,
                                sent,
                                failed
                            );
                        }
                        Err(e) => {
                            let (sent, failed) = self.get_stats();
                            eprintln!(
                                "パケット送信失敗: {} (成功: {}, 失敗: {})",
                                e, sent, failed
                            );
                        }
                    }
                }

                if packet_count > 0 {
                    let (sent, failed) = self.get_stats();
                    println!("==== パケット統計情報 ====");
                    println!("送信成功: {} パケット", sent);
                    println!("送信失敗: {} パケット", failed);
                    if sent + failed > 0 {
                        println!("成功率: {:.2}%", (sent as f64 / (sent + failed) as f64) * 100.0);
                    }
                    println!("========================");
                }

                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.packets_sent.load(Ordering::Relaxed),
            self.packets_failed.load(Ordering::Relaxed)
        )
    }
}

pub async fn inject_packet() -> Result<(), PacketError> {
    let interface = select_device()
        .map_err(|e| PacketError::DeviceError(e.to_string()))?;

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