use crate::host_ids::ip_header::{parse_ip_header, IpHeader};
use crate::host_ids::ip_reassembly::IpReassembler;
use crate::host_ids::tcp_header::{parse_tcp_header, parse_tcp_options};
use crate::host_ids::tcp_stream::{TcpStream, TcpStreamKey, TCP_SYN};
use chrono::{DateTime, Local};
use std::collections::HashMap;
use std::time::SystemTime;

// パケットを処理
pub fn process_packet<>(
    packet: &pcap::Packet,
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    ip_reassembler: &mut IpReassembler,
) -> Result<(), Box<dyn std::error::Error>> {
    let arrival_time = SystemTime::now();
    let eth_header_size = 14; // Ethernetヘッダーのサイズ
    if packet.data.len() <= eth_header_size {
        return Ok(());
    }

    let ip_data = &packet.data[eth_header_size..];

    if let Some((ip_header, ip_header_size)) = parse_ip_header(ip_data) {
        let payload = &ip_data[ip_header_size..];

        // IPの再構築を試みる
        if let Some(reassembled_packet) = ip_reassembler.process_packet(&ip_header, payload) {
            // 再構築されたパケットを処理
            match process_reassembled_packet(
                &ip_header,
                &reassembled_packet,
                streams,
                arrival_time,
            ) {
                Ok(_) => (),
                Err(e) => eprintln!("Error processing reassembled packet: {}", e),
            }
        } else {
            // フラグメントされていないパケットまたは再構築が完了していないパケットの処理
            match process_tcp_packet(&ip_header, payload, streams, arrival_time) {
                Ok(_) => (),
                Err(e) => eprintln!("Error processing TCP packet: {}", e),
            }
        }
    }

    // 100パケットごとにIP再構築のキャッシュをクリーンアップ
    if packet.header.len % 100 == 0 {
        ip_reassembler.cleanup();
    }

    Ok(())
}

fn process_reassembled_packet(
    ip_header: &IpHeader,
    packet: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    if ip_header.protocol != 6 {
        // TCPのプロトコル番号は6
        return Ok(());
    }

    if let Some((tcp_header, tcp_header_size)) = parse_tcp_header(packet) {
        let payload = &packet[tcp_header_size..];
        process_tcp_header_and_payload(ip_header, &tcp_header, payload, streams, arrival_time)?;
    }

    Ok(())
}

fn process_tcp_packet(
    ip_header: &IpHeader,
    tcp_data: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    if ip_header.protocol != 6 {
        // TCPのプロトコル番号は6
        return Ok(());
    }

    if let Some((tcp_header, tcp_header_size)) = parse_tcp_header(tcp_data) {
        let payload = &tcp_data[tcp_header_size..];
        process_tcp_header_and_payload(ip_header, &tcp_header, payload, streams, arrival_time)?;
    }

    Ok(())
}

// TCPヘッダーとペイロードを処理
fn process_tcp_header_and_payload(
    ip_header: &IpHeader,
    tcp_header: &crate::host_ids::tcp_header::TcpHeader,
    payload: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    match process_tcp_data(
        ip_header,
        tcp_header,
        payload,
        streams,
        arrival_time,
    ) {
        Ok(_) => (),
        Err(e) => eprintln!("Error processing TCP data: {}", e),
    }
    Ok(())
}

fn process_tcp_data(
    ip_header: &IpHeader,
    tcp_header: &crate::host_ids::tcp_header::TcpHeader,
    payload: &[u8],
    streams: &mut HashMap<TcpStreamKey, TcpStream>,
    arrival_time: SystemTime,
) -> Result<(), Box<dyn std::error::Error>> {
    let stream_key = (
        ip_header.src_ip,
        tcp_header.src_port,
        ip_header.dst_ip,
        tcp_header.dst_port,
    );
    let reverse_key = (
        ip_header.dst_ip,
        tcp_header.dst_port,
        ip_header.src_ip,
        tcp_header.src_port,
    );

    // クライアントからのパケットかどうかを判断
    let is_from_client = if streams.contains_key(&stream_key) {
        true
    } else if streams.contains_key(&reverse_key) {
        false
    } else {
        // 新しいストリームを開始
        if tcp_header.flags & TCP_SYN != 0 {
            let mut new_stream = TcpStream::new(tcp_header.seq_num, 0);
            let options_end = (tcp_header.data_offset as usize * 4).saturating_sub(20);
            if payload.len() >= options_end {
                if let Some(mss) = parse_tcp_options(&payload[..options_end]) {
                    new_stream.set_mss(true, mss);
                }
            }
            streams.insert(stream_key, new_stream);
        }
        true
    };

    let stream_key = if is_from_client { stream_key } else { reverse_key };

    // ストリームが存在する場合はデータを更新
    if let Some(stream) = streams.get_mut(&stream_key) {
        // サーバーからのSYNパケットの場合、MSSを設定
        if tcp_header.flags & TCP_SYN != 0 && !is_from_client {
            let options_end = (tcp_header.data_offset as usize * 4).saturating_sub(20);
            if payload.len() >= options_end {
                if let Some(mss) = parse_tcp_options(&payload[..options_end]) {
                    stream.set_mss(false, mss);
                }
            }
        }

        // ストリームの状態を更新
        stream.update(
            is_from_client,
            tcp_header.seq_num,
            tcp_header.ack_num,
            tcp_header.flags,
            payload,
            tcp_header.window,
        );

        stream.arrival_time = arrival_time;

        println!("Arrival time: {}", arrival_time_to_string(arrival_time));
        println!(
            "Stream: {}:{} -> {}:{}",
            stream_key.0, tcp_header.src_port, stream_key.2, tcp_header.dst_port
        );


        // ストリームが閉じられた場合、ストリームを削除
        if stream.state == crate::host_ids::tcp_stream::TcpState::Closed {
            streams.remove(&stream_key);
        }
    }

    Ok(())
}

// SystemTimeを文字列に変換する
fn arrival_time_to_string(arrival_time: SystemTime) -> String {
    let datetime: DateTime<Local> = arrival_time.into();
    datetime.format("%Y-%m-%d %H:%M:%S.%3f %Z").to_string()
}
