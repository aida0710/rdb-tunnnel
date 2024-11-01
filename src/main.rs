use crate::select_device::select_device;
use dotenv::dotenv;
use log::{error, info};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tokio::task::{self, JoinHandle};
use tokio::time::{sleep, Duration};
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

// タスクの状態を追跡する構造体
#[derive(Debug)]
struct TaskState {
    polling_active: bool,
    writer_active: bool,
    analysis_active: bool,
}

impl TaskState {
    fn new() -> Self {
        Self {
            polling_active: false,
            writer_active: false,
            analysis_active: false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), InitProcessError> {
    // 初期化処理
    setup_logger().map_err(|e| InitProcessError::LoggerError(e.to_string()))?;
    dotenv().map_err(|e| InitProcessError::EnvFileReadError(e.to_string()))?;

    // 環境変数の取得
    let timescale_host = dotenv::var("TIMESCALE_DB_HOST").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_user = dotenv::var("TIMESCALE_DB_USER").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_port = dotenv::var("TIMESCALE_DB_PORT").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?.parse::<u16>().map_err(|e| InitProcessError::EnvVarParseError(e.to_string()))?;
    let timescale_password = dotenv::var("TIMESCALE_DB_PASSWORD").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let timescale_db = dotenv::var("TIMESCALE_DB_DATABASE").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let tun_ip = dotenv::var("TAP_IP").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;
    let tun_mask = dotenv::var("TAP_MASK").map_err(|e| InitProcessError::EnvVarError(e.to_string()))?;

    // データベース接続
    Database::connect(&timescale_host, timescale_port, &timescale_user, &timescale_password, &timescale_db)
        .await
        .map_err(|e| InitProcessError::DatabaseConnectionError(e.to_string()))?;

    // 仮想インターフェースのセットアップ
    let virtual_interface = Iface::new("tap0", Mode::Tap)
        .map_err(|e| InitProcessError::VirtualInterfaceError(e.to_string()))?;
    info!("仮想NICの作成に成功しました: {}", virtual_interface.name());

    setup_interface("tap0", format!("{}/{}", tun_ip, tun_mask).as_str()).await?;

    let interface = select_device()
        .map_err(|e| InitProcessError::DeviceSelectionError(e.to_string()))?;
    info!("デバイスの選択に成功しました: {}", interface.name);

    // シャットダウンチャネルの作成
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let task_state = Arc::new(Mutex::new(TaskState::new()));

    // タスクの生成
    let polling_interface = interface.clone();
    let analysis_interface = interface.clone();

    let polling_shutdown = shutdown_tx.subscribe();
    let writer_shutdown = shutdown_tx.subscribe();
    let analysis_shutdown = shutdown_tx.subscribe();

    let task_state_polling = task_state.clone();
    let task_state_writer = task_state.clone();
    let task_state_analysis = task_state.clone();

    let polling_handle = spawn_monitored_task(
        "ポーリング",
        task_state_polling,
        polling_shutdown,
        || async {
            inject_packet(polling_interface).await.map_err(|e| e.to_string())
        },
    );

    let writer_handle = spawn_monitored_task(
        "ライター",
        task_state_writer,
        writer_shutdown,
        || async {
            start_packet_writer().await;
            Ok(())
        },
    );

    let analysis_handle = spawn_monitored_task(
        "分析",
        task_state_analysis,
        analysis_shutdown,
        || async {
            packet_analysis::packet_analysis(analysis_interface)
                .await
                .map_err(|e| e.to_string())
        },
    );

    // メインループ
    loop {
        tokio::select! {
            // タスクの監視
            _ = polling_handle => {
                error!("ポーリングタスクが予期せず終了しました");
                break;
            }
            _ = writer_handle => {
                error!("ライタータスクが予期せず終了しました");
                break;
            }
            _ = analysis_handle => {
                error!("分析タスクが予期せず終了しました");
                break;
            }
            // Ctrl+C の処理
            _ = tokio::signal::ctrl_c() => {
                info!("シャットダウン信号を受信しました");
                let _ = shutdown_tx.send(());

                // 全てのタスクが終了するまで待機
                for _ in 0..10 {
                    let state = task_state.lock().await;
                    if !state.polling_active && !state.writer_active && !state.analysis_active {
                        info!("全てのタスクが正常に終了しました");
                        return Ok(());
                    }
                    drop(state);
                    sleep(Duration::from_millis(100)).await;
                }

                error!("タスクの終了待機がタイムアウトしました");
                break;
            }
        }
    }

    error!("アプリケーションが異常終了します");
    std::process::exit(1);
}

fn spawn_monitored_task<F, Fut>(
    task_name: &'static str,
    task_state: Arc<Mutex<TaskState>>,
    mut shutdown: broadcast::Receiver<()>,
    future: F,
) -> JoinHandle<Result<(), String>>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: futures::Future<Output=Result<(), String>> + Send + 'static,
{
    task::spawn(async move {
        {
            let mut state = task_state.lock().await;
            match task_name {
                "ポーリング" => state.polling_active = true,
                "ライター" => state.writer_active = true,
                "分析" => state.analysis_active = true,
                _ => {}
            }
        }

        let result = tokio::select! {
            result = future() => result,
            _ = shutdown.recv() => {
                info!("{}タスクをシャットダウンしています...", task_name);
                Ok(())
            }
        };

        {
            let mut state = task_state.lock().await;
            match task_name {
                "ポーリング" => state.polling_active = false,
                "ライター" => state.writer_active = false,
                "分析" => state.analysis_active = false,
                _ => {}
            }
        }

        result
    })
}