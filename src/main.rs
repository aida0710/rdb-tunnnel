use std::process;
use std::sync::Arc;
use tokio;

mod core;
mod network;
mod security;
mod storage;

use crate::core::{Configuration, PacketPipeline, TunnelError};
use crate::network::{PacketCapture, PacketInjector};
use crate::security::firewall::Firewall;
use crate::security::idps::IDPSAnalyzer;
use crate::storage::repository::{PacketRepository, TimescaleRepository};

#[tokio::main]
async fn main() {
    // ロガーの初期化
    env_logger::init();

    // 設定の読み込み
    let config = match Configuration::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("設定の読み込みに失敗しました: {}", e);
            process::exit(1);
        }
    };

    // アプリケーションの起動
    if let Err(e) = run_application(config).await {
        eprintln!("アプリケーションの実行中にエラーが発生しました: {}", e);
        process::exit(1);
    }
}

async fn run_application(config: Configuration) -> Result<(), TunnelError> {
    log::info!("RDB トンネルを起動しています...");

    // ネットワークインターフェースの初期化
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == config.network.interface)
        .ok_or_else(|| TunnelError::Config(format!(
            "指定されたインターフェース '{}' が見つかりません",
            config.network.interface
        )))?;

    // コンポーネントの初期化
    log::info!("コンポーネントを初期化しています...");

    // パケットキャプチャーの初期化
    let packet_capture = PacketCapture::new(
        interface.clone(),
        config.network.buffer_size,
    );

    // パケット注入の初期化
    let packet_injector = PacketInjector::new(interface);

    // IDPSの初期化
    let idps = IDPSAnalyzer::new();

    // 基本的なIDPSルールの設定
    if config.security.idps_enabled {
        setup_default_idps_rules(&idps).await;
    }

    // ファイアウォールの初期化
    let firewall = Firewall::new();

    // 基本的なファイアウォールルールの設定
    if config.security.firewall_enabled {
        setup_default_firewall_rules(&firewall).await;
    }

    // データベースリポジトリの初期化
    let repository = Arc::new(TimescaleRepository::new(&config.database).await?);

    // データベースマイグレーションの実行
    log::info!("データベースマイグレーションを実行しています...");
    let client = repository.get_client().await?;
    storage::migrations::run_migrations(&client).await?;

    // クリーンアップタスクの開始
    let cleanup_repository = Arc::clone(&repository);
    tokio::spawn(async move {
        run_cleanup_task(cleanup_repository).await;
    });

    // メインのパケットパイプラインの構築と起動
    log::info!("パケットパイプラインを開始しています...");
    let pipeline = PacketPipeline::new(
        packet_capture,
        idps,
        firewall,
        repository,
        packet_injector,
    );

    // シグナルハンドラの設定
    let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
    setup_signal_handler(shutdown_sender);

    // パイプラインの実行
    log::info!("RDB トンネルが稼働中です");
    tokio::select! {
        result = pipeline.start() => {
            if let Err(e) = result {
                log::error!("パイプラインでエラーが発生しました: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_receiver => {
            log::info!("シャットダウンシグナルを受信しました");
            pipeline.stop().await;
        }
    }

    log::info!("RDB トンネルを正常にシャットダウンしました");
    Ok(())
}

async fn setup_default_idps_rules(idps: &IDPSAnalyzer) {
    use security::idps::rules::{Rule, RuleAction, RuleCondition};

    // SYNフラッド検出ルール
    idps.add_rule(Rule {
        name: "SYN Flood Detection".to_string(),
        description: "SYNフラッド攻撃を検出します".to_string(),
        conditions: vec![
            RuleCondition::Protocol(6), // TCP
            RuleCondition::PacketSize(security::idps::rules::RangeCondition {
                min: Some(40),
                max: Some(60),
            }),
        ],
        action: RuleAction::Alert,
        priority: 100,
    }).await;

    // 不正なTCPフラグの組み合わせ検出
    idps.add_rule(Rule {
        name: "Invalid TCP Flags".to_string(),
        description: "不正なTCPフラグの組み合わせを検出します".to_string(),
        conditions: vec![
            RuleCondition::Protocol(6),
        ],
        action: RuleAction::Block,
        priority: 90,
    }).await;
}

async fn setup_default_firewall_rules(firewall: &Firewall) {
    use security::firewall::rules::{FirewallAction, FirewallCondition, FirewallRule};

    // SSHアクセス制限
    firewall.add_rule(FirewallRule {
        name: "SSH Access".to_string(),
        description: "SSH接続を制限します".to_string(),
        conditions: vec![
            FirewallCondition::DestinationPort(22),
            FirewallCondition::Protocol(6),
        ],
        action: FirewallAction::Drop,
        priority: 100,
    }).await;

    // 内部ネットワークの保護
    firewall.add_rule(FirewallRule {
        name: "Internal Network Protection".to_string(),
        description: "内部ネットワークへの直接アクセスを制限します".to_string(),
        conditions: vec![
            FirewallCondition::DestinationIP("10.0.0.0/8".parse().unwrap()),
        ],
        action: FirewallAction::Drop,
        priority: 90,
    }).await;
}

async fn run_cleanup_task(repository: Arc<TimescaleRepository>) {
    use chrono::{Duration, Utc};

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // 1時間ごと

    loop {
        interval.tick().await;

        let cleanup_date = Utc::now() - Duration::days(7); // 7日以上前のパケットを削除
        if let Err(e) = repository.delete_old_packets(cleanup_date).await {
            log::error!("古いパケットの削除中にエラーが発生しました: {}", e);
        }
    }
}

fn setup_signal_handler(sender: tokio::sync::oneshot::Sender<()>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        tokio::spawn(async move {
            let mut sigint = signal(SignalKind::interrupt()).unwrap();
            sigint.recv().await;
            let _ = sender.send(());
        });
    }

    #[cfg(windows)]
    {
        use tokio::signal::windows::ctrl_c;
        tokio::spawn(async move {
            let mut stream = ctrl_c().unwrap();
            stream.recv().await;
            let _ = sender.send(());
        });
    }
}

// テストモジュール
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_configuration_loading() {
        // 環境変数の設定
        std::env::set_var("NETWORK_INTERFACE", "test0");
        std::env::set_var("DB_HOST", "localhost");
        std::env::set_var("DB_USER", "test");
        std::env::set_var("DB_PASSWORD", "test");
        std::env::set_var("DB_NAME", "test_db");

        let config = Configuration::from_env().expect("設定の読み込みに失敗しました");
        assert_eq!(config.network.interface, "test0");
        assert_eq!(config.database.host, "localhost");
    }

    #[tokio::test]
    async fn test_packet_pipeline() {
        // パイプラインのモックテスト実装
        // ...
    }
}