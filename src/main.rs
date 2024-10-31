use crate::select_device::select_device;
use dotenv::dotenv;
use log::error;
use tokio::task;
use tun_tap::{Iface, Mode};

mod select_device;
mod database;
mod error;
mod db_read;
mod packet_header;
mod db_write;
mod firewall;
mod firewall_packet;
mod virtual_interface;
mod setup_logger;
mod packet_analysis;

use crate::database::database::Database;
use crate::db_read::inject_packet;
use crate::db_write::start_packet_writer;
use crate::error::InitProcessError;
use crate::setup_logger::setup_logger;
use crate::virtual_interface::setup_interface;

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
    let virtual_interface = Iface::new("tap0", Mode::Tap)
        .map_err(|e| InitProcessError::VirtualInterfaceError(e.to_string()))?;
    println!("仮想NICの作成に成功しました: {}", virtual_interface.name());

    // IPアドレスの設定とインターフェースの有効化
    //setup_interface("tun0", "192.168.0.150/24").await?;
    setup_interface("tap0", format!("{}/{}", tun_ip, tun_mask).as_str()).await?;

    let interface = select_device()
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    println!("デバイスの選択に成功しました: {}", interface.name);

    let polling_interface = interface.clone();
    let analysis_interface = interface.clone();

    let polling_handle = task::spawn(async move {
        println!("非同期でポーリングを開始します");
        inject_packet(polling_interface).await
    });

    let writer_handle = task::spawn(async {
        println!("非同期でパケットの書き込みを開始します");
        start_packet_writer().await
    });

    let analysis_handle = task::spawn(async move {
        println!("非同期でパケット分析を開始します");
        if let Err(e) = packet_analysis::packet_analysis(analysis_interface).await {
            error!("パケット分析でエラーが発生: {:?}", e);
        }
    });

    // 全てのタスクを待機
    tokio::select! {
        _ = polling_handle => println!("ポーリングタスクが終了しました"),
        _ = writer_handle => println!("ライタータスクが終了しました"),
        _ = analysis_handle => println!("分析タスクが終了しました"),
        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl+C を受信。終了処理を開始します...");
            std::process::exit(0);
        }
    }

    Ok(())
}