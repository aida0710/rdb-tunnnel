use async_trait::async_trait;
use crate::error::Result;
use super::PacketAnalyzer;

pub struct TcpAnalyzer {
    // TCP固有の設定やステート
}

#[async_trait]
impl PacketAnalyzer for TcpAnalyzer {
    async fn analyze(&mut self, packet: &[u8]) -> Result<()> {
        // TCPパケットの分析ロジック
        Ok(())
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::TCP
    }
}