use crate::database::database::Database;
use crate::database::error::DbError;
use crate::database::execute_query::ExecuteQuery;
use std::net::IpAddr;

pub struct PacketInfo {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: Option<i32>,
    dst_port: Option<i32>,
    protocol: i16,
    timestamp: String,
    data: Vec<u8>,
    raw_packet: Vec<u8>,
}

pub async fn rdb_tunnel_packet_read(
    limit: i64,
    offset: i64,
) -> Result<Vec<PacketInfo>, DbError> {
    let db = Database::get_database();
    let query = "
        SELECT src_ip, dst_ip, src_port, dst_port, protocol,
               to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS.US') as timestamp,
               data, raw_packet
        FROM packets
        ORDER BY timestamp DESC
        LIMIT $1 OFFSET $2
        ";
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[&limit, &offset];

    let rows = db.query(query, params).await?;

    let packet_infos: Vec<PacketInfo> = rows
        .into_iter()
        .map(|row| PacketInfo {
            src_ip: row.get("src_ip"),
            dst_ip: row.get("dst_ip"),
            src_port: row.get("src_port"),
            dst_port: row.get("dst_port"),
            protocol: row.get("protocol"),
            timestamp: row.get("timestamp"),
            data: row.get("data"),
            raw_packet: row.get("raw_packet"),
        })
        .collect();

    Ok(packet_infos)
}

pub async fn rdb_tunnel_packet_write(packet: &PacketInfo) -> Result<(), DbError> {
    let db = Database::get_database();
    let query = "
        INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, timestamp, data, raw_packet)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    ";
    let params: &[&(dyn tokio_postgres::types::ToSql + Sync)] = &[
        &packet.src_ip,
        &packet.dst_ip,
        &packet.src_port,
        &packet.dst_port,
        &packet.protocol,
        &packet.timestamp,
        &packet.data,
        &packet.raw_packet,
    ];

    db.execute(query, params).await?;
    Ok(())
}

pub async fn print_packet_summary(limit: i64, offset: i64) -> Result<(), DbError> {
    let packet_infos = rdb_tunnel_packet_read(limit, offset).await?;
    for (index, packet) in packet_infos.iter().enumerate() {
        println!("Packet {}", index + 1);
        println!("  Source IP: {}", packet.src_ip);
        println!("  Destination IP: {}", packet.dst_ip);
        println!("  Source Port: {:?}", packet.src_port);
        println!("  Destination Port: {:?}", packet.dst_port);
        println!("  Protocol: {}", packet.protocol);
        println!("  Timestamp: {}", packet.timestamp);
        println!("  Data Length: {} bytes", packet.data.len());
        println!("  Raw Packet Length: {} bytes", packet.raw_packet.len());
        println!();
    }
    Ok(())
}