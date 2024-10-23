use async_trait::async_trait;
use crate::error::types::Result;

#[async_trait]
pub trait PacketProcessor {
    async fn process(&mut self, packet: &[u8]) -> Result<()>;
    fn get_statistics(&self) -> PacketStatistics;
}

pub struct PacketStatistics {
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub errors_encountered: u64,
}

pub struct DefaultPacketProcessor {
    statistics: PacketStatistics,
    analyzers: Vec<Box<dyn PacketAnalyzer>>,
    filters: Vec<Box<dyn PacketFilter>>,
}

#[async_trait]
impl PacketProcessor for DefaultPacketProcessor {
    async fn process(&mut self, packet: &[u8]) -> Result<()> {
        // パケット処理のメイン実装
        self.statistics.packets_processed += 1;
        self.statistics.bytes_processed += packet.len() as u64;

        // フィルタリング
        if !self.should_process(packet) {
            return Ok(());
        }

        // 分析
        for analyzer in &mut self.analyzers {
            if let Err(e) = analyzer.analyze(packet).await {
                self.statistics.errors_encountered += 1;
                log::error!("パケット分析エラー: {}", e);
            }
        }

        Ok(())
    }

    fn get_statistics(&self) -> PacketStatistics {
        self.statistics.clone()
    }
}