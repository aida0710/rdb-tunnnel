use crate::core::error::TunnelResult;
use crate::network::capture::PacketCapture;
use crate::network::injection::PacketInjector;
use crate::security::firewall::Firewall;
use crate::security::idps::IDPSAnalyzer;
use crate::storage::repository::PacketRepository;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use crate::storage::models::packet::StoredPacket;

pub struct PacketPipeline {
    capture: Arc<PacketCapture>,
    idps: Arc<IDPSAnalyzer>,
    firewall: Arc<Firewall>,
    storage: Arc<dyn PacketRepository>,
    injection: Arc<PacketInjector>,
    running: Arc<Mutex<bool>>,
}

impl PacketPipeline {
    pub fn new(
        capture: PacketCapture,
        idps: IDPSAnalyzer,
        firewall: Firewall,
        storage: Arc<dyn PacketRepository>,
        injection: PacketInjector,
    ) -> Self {
        Self {
            capture: Arc::new(capture),
            idps: Arc::new(idps),
            firewall: Arc::new(firewall),
            storage,
            injection: Arc::new(injection),
            running: Arc::new(Mutex::new(true)),
        }
    }

    pub async fn start(&self) -> TunnelResult<()> {
        println!("パケットパイプラインを開始します...");

        // 受信用タスクの開始
        let receive_task = self.clone().start_receive_pipeline();

        // 送信用タスクの開始
        let transmit_task = self.clone().start_transmit_pipeline();

        // 両方のタスクを実行
        tokio::try_join!(receive_task, transmit_task)?;

        Ok(())
    }

    async fn start_receive_pipeline(self) -> TunnelResult<()> {
        while *self.running.lock().await {
            match self.capture.next_packet().await {
                Ok(packet) => {
                    // IDPSチェック
                    if !self.idps.analyze(&packet).await? {
                        continue;
                    }

                    // ファイアウォールチェック
                    if !self.firewall.check(&packet).await? {
                        continue;
                    }

                    // パケットの変換と保存
                    let stored_packet = StoredPacket::from_network_packet(&packet);
                    self.storage.store(&stored_packet).await?;
                }
                Err(e) => {
                    eprintln!("パケットの受信中にエラーが発生しました: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Ok(())
    }

    async fn start_transmit_pipeline(self) -> TunnelResult<()> {
        while *self.running.lock().await {
            match self.storage.fetch_for_self().await {
                Ok(stored_packets) => {
                    for stored_packet in stored_packets {
                        // StoredPacketをネットワークパケットに変換
                        let packet = stored_packet.into_network_packet();
                        if let Err(e) = self.injection.inject(&packet).await {
                            eprintln!("パケットの注入中にエラーが発生しました: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("パケットの取得中にエラーが発生しました: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }
    
    pub async fn stop(&self) {
        let mut running = self.running.lock().await;
        *running = false;
    }
}

impl Clone for PacketPipeline {
    fn clone(&self) -> Self {
        Self {
            capture: Arc::clone(&self.capture),
            idps: Arc::clone(&self.idps),
            firewall: Arc::clone(&self.firewall),
            storage: Arc::clone(&self.storage),
            injection: Arc::clone(&self.injection),
            running: Arc::clone(&self.running),
        }
    }
}