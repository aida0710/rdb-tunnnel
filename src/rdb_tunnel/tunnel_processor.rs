use crate::rdb_tunnel::db_read::print_packet_summary;
use crate::rdb_tunnel::db_write::rdb_tunnel_packet_write;

pub async fn rdb_tunnel(ethernet_packet: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // パケットの書き込み
    rdb_tunnel_packet_write(&ethernet_packet).await?;

    // パケットの読み込みと表示（最新の10件を表示）
    print_packet_summary(10, 0).await?;

    Ok(())
}