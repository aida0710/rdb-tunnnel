use crate::select_device::select_device;
use dotenv::dotenv;

mod select_device;
mod host_ids;
mod vpn;
mod real_time_analytics;
mod web_console;
mod database;
pub mod packet_analysis;
mod error;

use crate::database::database::Database;
use crate::error::InitProcessError;
use packet_analysis::packet_analysis;

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    dotenv().map_err(|e| InitProcessError::EnvFileReadError(e.to_string()))?;

    let timescale_host = dotenv::var("TIMESCALE_HOST").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_user = dotenv::var("TIMESCALE_USER").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_port = dotenv::var("TIMESCALE_PORT").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?.parse::<u16>().map_err(|e| InitProcessError::EnvVarParseError(e.to_string()))?;
    let timescale_password = dotenv::var("TIMESCALE_PASSWORD").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_db = dotenv::var("TIMESCALE_DB").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;

    // データベースへの接続
    Database::connect(&timescale_host, timescale_port, &timescale_user, &timescale_password, &timescale_db)
        .await
        .map_err(|e| InitProcessError::DatabaseConnectionError(e.to_string()))?;

    // デバイスの選択
    let interface = select_device()
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    println!("デバイスの選択に成功しました: {}", interface.name);

    // 非同期のパケット取得とnicに再注入

    // パケットの解析とデータベースへの保存
    if let Err(e) = packet_analysis(interface) {
        println!("パケットの解析に失敗しました: {}", InitProcessError::PacketAnalysisError(e.to_string()));
    }

    Ok(())
}