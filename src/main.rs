use crate::select_device::select_device;
use dotenv::dotenv;
use tokio::task;
use tun_tap::{Iface, Mode};

mod select_device;
mod inspector;
mod database;
pub mod packet_analysis;
mod error;
mod db_read;
mod packet_header;
mod db_write;
mod firewall;
mod firewall_packet;
mod virtual_interface;
mod setup_logger;

use crate::database::database::Database;
use crate::db_read::inject_packet;
use crate::db_write::start_packet_writer;
use crate::error::InitProcessError;
use crate::setup_logger::setup_logger;
use crate::virtual_interface::setup_interface;
use packet_analysis::packet_analysis;

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    setup_logger().map_err(|e| InitProcessError::LoggerError(e.to_string()))?;

    dotenv().map_err(|e| InitProcessError::EnvFileReadError(e.to_string()))?;

    let timescale_host = dotenv::var("TIMESCALE_DB_HOST").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_user = dotenv::var("TIMESCALE_DB_USER").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_port = dotenv::var("TIMESCALE_DB_PORT").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?.parse::<u16>().map_err(|e| InitProcessError::EnvVarParseError(e.to_string()))?;
    let timescale_password = dotenv::var("TIMESCALE_DB_PASSWORD").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_db = dotenv::var("TIMESCALE_DB_DATABASE").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let tun_ip = dotenv::var("TAP_IP").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let tun_mask = dotenv::var("TAP_MASK").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;

    // データベースへの接続
    Database::connect(&timescale_host, timescale_port, &timescale_user, &timescale_password, &timescale_db)
        .await
        .map_err(|e| InitProcessError::DatabaseConnectionError(e.to_string()))?;

    // 仮想NIC(tun0)の作成
    let interface = Iface::new("tap0", Mode::Tap)
        .map_err(|e| InitProcessError::VirtualInterfaceError(e.to_string()))?;
    println!("仮想NICの作成に成功しました: {}", interface.name());

    // IPアドレスの設定とインターフェースの有効化
    //setup_interface("tun0", "192.168.0.150/24").await?;
    setup_interface("tap0", format!("{}/{}", tun_ip, tun_mask).as_str()).await?;

    // デバイスの選択
    let interface = select_device()
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    println!("デバイスの選択に成功しました: {}", interface.name);

    // 非同期のパケット取得とnicに再注入
    let polling_interface = interface.clone();
    task::spawn(async move {
        println!("非同期でポーリングを開始します");
        inject_packet(polling_interface).await.expect("パケットの再注入に失敗しました");
    });

    let analysis_interface = interface.clone();
    task::spawn(async move {
        start_packet_writer().await;
    });

    // パケットの解析とデータベースへの保存
    if let Err(e) = packet_analysis(analysis_interface).await {
        println!("パケットの解析に失敗しました: {}", InitProcessError::PacketAnalysisError(e.to_string()));
    }

    Ok(())
}