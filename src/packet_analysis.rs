use crate::db_write::rdb_tunnel_packet_write;
use log::{debug, error, info};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::NetworkInterface;
use std::io;
use thiserror::Error;
use tokio::sync::mpsc;
use crate::error::InitProcessError;

#[derive(Error, Debug)]
pub enum PacketAnalysisError {
    #[error("ネットワークエラー: {0}")]
    NetworkError(String),

    #[error("IOエラー: {0}")]
    IoError(#[from] io::Error),

    #[error("インターフェースエラー: {0}")]
    InterfaceError(String),
}

impl From<PacketAnalysisError> for InitProcessError {
    fn from(err: PacketAnalysisError) -> Self {
        InitProcessError::PacketAnalysisError(err.to_string())
    }
}

async fn handle_interface(interface: NetworkInterface) -> Result<(), PacketAnalysisError> {
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(PacketAnalysisError::InterfaceError(
            "未対応のチャンネルタイプです".to_string()
        )),
        Err(e) => return Err(PacketAnalysisError::NetworkError(e.to_string())),
    };

    info!("インターフェース {} でパケット受信を開始しました", interface.name);

    loop {
        match rx.next() {
            Ok(ethernet_packet) => {
                let packet_data = ethernet_packet.to_vec();
                tokio::spawn(async move {
                    if let Err(e) = rdb_tunnel_packet_write(&packet_data).await {
                        error!("パケットの書き込みに失敗しました: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("パケットの読み取り中にエラーが発生しました: {}", e);
                return Err(PacketAnalysisError::NetworkError(e.to_string()));
            }
        }
    }
}

pub async fn packet_analysis(interface: NetworkInterface) -> Result<(), PacketAnalysisError> {
    let interfaces = datalink::interfaces();
    let tap0_interface = interfaces
        .into_iter()
        .find(|iface| iface.name == "tap0")
        .ok_or_else(|| PacketAnalysisError::InterfaceError(
            "tap0 インターフェースが見つかりません".to_string()
        ))?;

    let interface_handle = tokio::spawn(async move {
        if let Err(e) = handle_interface(interface).await {
            error!("メインインターフェースでエラーが発生: {}", e);
        }
    });

    let tap0_handle = tokio::spawn(async move {
        if let Err(e) = handle_interface(tap0_interface).await {
            error!("tap0インターフェースでエラーが発生: {}", e);
        }
    });

    tokio::select! {
        result1 = interface_handle => {
            if let Err(e) = result1 {
                error!("メインインターフェースのタスクでエラーが発生: {}", e);
                return Err(PacketAnalysisError::NetworkError(e.to_string()));
            }
        }
        result2 = tap0_handle => {
            if let Err(e) = result2 {
                error!("tap0インターフェースのタスクでエラーが発生: {}", e);
                return Err(PacketAnalysisError::NetworkError(e.to_string()));
            }
        }
    }

    Ok(())
}

pub fn check_interfaces() -> Result<(), PacketAnalysisError> {
    let interfaces = datalink::interfaces();

    println!("利用可能なインターフェース:");
    for iface in interfaces.iter() {
        println!("- {}: {}", iface.name, if iface.is_up() { "UP" } else { "DOWN" });
    }

    if !interfaces.iter().any(|iface| iface.name == "tap0") {
        return Err(PacketAnalysisError::InterfaceError(
            "tap0インターフェースが見つかりません".to_string()
        ));
    }

    Ok(())
}