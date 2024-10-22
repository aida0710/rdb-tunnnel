use crate::rdb_tunnel;

pub async fn inject_packet() {
    rdb_tunnel::print_packet_summary(20, 10).await.expect("エラーが発生しましたｓｓｓ");
}