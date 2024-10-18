use crate::rdb_tunnel::firewall::{Filter, IpFirewall, Policy};
use crate::rdb_tunnel::firewall_packet::FirewallPacket;
use crate::rdb_tunnel::packet_header::{parse_ip_header, parse_next_ip_header};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::net::IpAddr;

pub fn rdb_tunnel(ethernet_packet: &[u8]) {
    // packetの簡単な解析
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    if let Some(ip_header) = parse_ip_header(&ethernet_packet) {
        let protocol = IpNextHeaderProtocol(ip_header.protocol);

        if protocol == IpNextHeaderProtocols::Tcp || protocol == IpNextHeaderProtocols::Udp {
            let payload_offset = match ip_header.version {
                4 => 20, // IPv4ヘッダーの最小サイズ
                6 => 40, // IPv6ヘッダーの固定サイズ
                _ => return, // 未知のIPバージョン
            };

            if ethernet_packet.len() > payload_offset {
                let next_ip_header = parse_next_ip_header(&ethernet_packet[payload_offset..]);
                src_port = next_ip_header.source_port;
                dst_port = next_ip_header.destination_port;
            } else {
                // lengthが足りない場合は終了
                return;
            }
        }

        // firewallの実行
        let mut firewall = IpFirewall::new(Policy::Blacklist);

        firewall.add_rule(Filter::IpAddress(IpAddr::V4("192.168.1.100".parse().unwrap())), 100);
        firewall.add_rule(Filter::Port(8080), 90);

        println!("Blacklist - Packet allowed: {}", firewall.check(FirewallPacket::new(ip_header.src_ip, ip_header.dst_ip, src_port, dst_port, ip_header.version, protocol)));

        // dbにデータを書き込み

        // ここにデータベースへの書き込みコードを追加
    } else {
        println!("IPヘッダーのパースに失敗しました");
    }

    //終了
}