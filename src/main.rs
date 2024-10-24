use crate::select_device::select_device;
use dotenv::dotenv;
use tokio::task;

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

use crate::database::database::Database;
use crate::db_read::inject_packet;
use crate::db_write::start_packet_writer;
use crate::error::InitProcessError;
use packet_analysis::packet_analysis;

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    dotenv().map_err(|e| InitProcessError::EnvFileReadError(e.to_string()))?;

    let timescale_host = dotenv::var("TIMESCALE_DB_HOST").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_user = dotenv::var("TIMESCALE_DB_USER").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_port = dotenv::var("TIMESCALE_DB_PORT").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?.parse::<u16>().map_err(|e| InitProcessError::EnvVarParseError(e.to_string()))?;
    let timescale_password = dotenv::var("TIMESCALE_DB_PASSWORD").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_db = dotenv::var("TIMESCALE_DB_DATABASE").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;

    // データベースへの接続
    Database::connect(&timescale_host, timescale_port, &timescale_user, &timescale_password, &timescale_db)
        .await
        .map_err(|e| InitProcessError::DatabaseConnectionError(e.to_string()))?;

    // デバイスの選択
    let interface = select_device()
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    println!("デバイスの選択に成功しました: {}", interface.name);

    // 非同期のパケット取得とnicに再注入
    task::spawn(async {
        inject_packet().await;
    });

    task::spawn(async {
        start_packet_writer().await;
    });

    // パケットの解析とデータベースへの保存
    if let Err(e) = packet_analysis(interface).await {
        println!("パケットの解析に失敗しました: {}", InitProcessError::PacketAnalysisError(e.to_string()));
    }

    Ok(())
}