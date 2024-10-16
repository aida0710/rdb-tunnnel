use pcap::Packet;
use crate::vpn::firewall::{Filter, IpFirewall, Policy};
use crate::vpn::packet_header::{parse_ip_header, parse_next_ip_header};

pub enum Protocol {
    Tcp = 6,
    Udp = 17,
}

pub fn rdb_vpn(mut packet: Packet) {

    // packetの簡単な解析
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;

    let ip_header = parse_ip_header(&mut packet);
    if ip_header.protocol == Protocol::Tcp as u8 || ip_header.protocol == Protocol::Udp as u8 {
        let next_ip_header = parse_next_ip_header(&mut packet);
        src_port = next_ip_header.source_port;
        dst_port = next_ip_header.destination_port;
    }

    // firewallの実行
    let mut firewall = IpFirewall::new(Policy::Blacklist);

    firewall.add_rule(Filter::IpAddress("192.168.1.100".parse().unwrap()), 100);
    firewall.add_rule(Filter::Port(8080), 90);

    println!("Blacklist - Packet 1 allowed: {}", firewall.check(ip_header, src_port, dst_port));

    // dbにデータを書き込み

    //終了
}