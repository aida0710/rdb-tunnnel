use crate::core::error::TunnelResult;
use crate::network::packet::{NetworkHeader, Packet, TransportHeader};
use pnet::datalink::{self, NetworkInterface};

pub struct PacketInjector {
    interface: NetworkInterface,
}

impl PacketInjector {
    pub fn new(interface: NetworkInterface) -> Self {
        Self { interface }
    }

    pub async fn inject(&self, packet: &Packet) -> TunnelResult<()> {
        let (mut tx, _) = match datalink::channel(&self.interface, Default::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(crate::core::error::TunnelError::Injection(
                "未サポートのチャネルタイプです".to_string()
            )),
            Err(e) => return Err(crate::core::error::TunnelError::Injection(
                format!("チャネルの作成に失敗しました: {}", e)
            )),
        };

        // パケットの再構築
        let mut buffer = Vec::new();
        self.build_packet(packet, &mut buffer)?;

        // パケットの送信
        match tx.send_to(&buffer, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(crate::core::error::TunnelError::Injection(
                format!("パケットの送信に失敗しました: {}", e)
            )),
            None => Err(crate::core::error::TunnelError::Injection(
                "パケットの送信に失敗しました".to_string()
            )),
        }
    }

    fn build_packet(&self, packet: &Packet, buffer: &mut Vec<u8>) -> TunnelResult<()> {
        // イーサネットヘッダーの構築
        buffer.extend_from_slice(&packet.ethernet.source);
        buffer.extend_from_slice(&packet.ethernet.destination);
        buffer.extend_from_slice(&packet.ethernet.ethertype.to_be_bytes());

        // ネットワーク層の構築
        match &packet.network {
            NetworkHeader::IPv4(ipv4) => {
                // バージョンとIHL
                let version_ihl = (ipv4.version << 4) | ipv4.ihl;
                buffer.push(version_ihl);

                // DSCP と ECN
                let dscp_ecn = (ipv4.dscp << 2) | ipv4.ecn;
                buffer.push(dscp_ecn);

                // 合計長
                buffer.extend_from_slice(&ipv4.total_length.to_be_bytes());

                // 識別子
                buffer.extend_from_slice(&ipv4.identification.to_be_bytes());

                // フラグとフラグメントオフセット
                let flags_offset = ((ipv4.flags as u16) << 13) | ipv4.fragment_offset;
                buffer.extend_from_slice(&flags_offset.to_be_bytes());

                // TTL, プロトコル, チェックサム
                buffer.push(ipv4.ttl);
                buffer.push(ipv4.protocol);
                buffer.extend_from_slice(&ipv4.checksum.to_be_bytes());

                // 送信元IPアドレス
                buffer.extend_from_slice(&ipv4.source.octets());

                // 宛先IPアドレス
                buffer.extend_from_slice(&ipv4.destination.octets());
            }
            NetworkHeader::IPv6(ipv6) => {
                // バージョン、トラフィッククラス、フローラベル
                let first_word = ((ipv6.version as u32) << 28) |
                    ((ipv6.traffic_class as u32) << 20) |
                    (ipv6.flow_label & 0xFFFFF);
                buffer.extend_from_slice(&first_word.to_be_bytes());

                // ペイロード長、次ヘッダー、ホップリミット
                buffer.extend_from_slice(&ipv6.payload_length.to_be_bytes());
                buffer.push(ipv6.next_header);
                buffer.push(ipv6.hop_limit);

                // 送信元IPv6アドレス
                buffer.extend_from_slice(&ipv6.source.octets());

                // 宛先IPv6アドレス
                buffer.extend_from_slice(&ipv6.destination.octets());
            }
        }

        // トランスポート層の構築
        if let Some(transport) = &packet.transport {
            match transport {
                TransportHeader::TCP(tcp) => {
                    // 送信元ポートと宛先ポート
                    buffer.extend_from_slice(&tcp.source_port.to_be_bytes());
                    buffer.extend_from_slice(&tcp.destination_port.to_be_bytes());

                    // シーケンス番号
                    buffer.extend_from_slice(&tcp.sequence_number.to_be_bytes());

                    // 確認応答番号
                    buffer.extend_from_slice(&tcp.acknowledgment_number.to_be_bytes());

                    // データオフセットとフラグ
                    let offset_flags: u16 = ((tcp.data_offset as u16 & 0xF) << 12) |
                        ((if tcp.flags.urg { 1u16 } else { 0u16 }) << 5) |
                        ((if tcp.flags.ack { 1u16 } else { 0u16 }) << 4) |
                        ((if tcp.flags.psh { 1u16 } else { 0u16 }) << 3) |
                        ((if tcp.flags.rst { 1u16 } else { 0u16 }) << 2) |
                        ((if tcp.flags.syn { 1u16 } else { 0u16 }) << 1) |
                        (if tcp.flags.fin { 1u16 } else { 0u16 });
                    buffer.extend_from_slice(&offset_flags.to_be_bytes());

                    // ウィンドウサイズ、チェックサム、緊急ポインタ
                    buffer.extend_from_slice(&tcp.window_size.to_be_bytes());
                    buffer.extend_from_slice(&tcp.checksum.to_be_bytes());
                    buffer.extend_from_slice(&tcp.urgent_pointer.to_be_bytes());
                }
                TransportHeader::UDP(udp) => {
                    // 送信元ポートと宛先ポート
                    buffer.extend_from_slice(&udp.source_port.to_be_bytes());
                    buffer.extend_from_slice(&udp.destination_port.to_be_bytes());

                    // 長さとチェックサム
                    buffer.extend_from_slice(&udp.length.to_be_bytes());
                    buffer.extend_from_slice(&udp.checksum.to_be_bytes());
                }
                TransportHeader::ICMP(icmp) => {
                    // タイプ、コード、チェックサム
                    buffer.push(icmp.icmp_type);
                    buffer.push(icmp.icmp_code);
                    buffer.extend_from_slice(&icmp.checksum.to_be_bytes());

                    // 残りのヘッダー
                    buffer.extend_from_slice(&icmp.rest_of_header.to_be_bytes());
                }
            }
        }

        // ペイロードの追加
        buffer.extend_from_slice(&packet.payload);

        Ok(())
    }

    // チェックサム計算のヘルパーメソッド
    fn calculate_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;

        // 16ビット単位で合計を計算
        for chunk in data.chunks(2) {
            let mut word = (chunk[0] as u32) << 8;
            if chunk.len() > 1 {
                word |= chunk[1] as u32;
            }
            sum = sum.wrapping_add(word);
        }

        // 上位16ビットを下位16ビットに折り返す
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        // 1の補数を取る
        !sum as u16
    }

    // IPヘッダーのチェックサム計算
    fn calculate_ip_checksum(&self, header: &[u8]) -> u16 {
        PacketInjector::calculate_checksum(header)
    }

    // TCPチェックサムの計算
    fn calculate_tcp_checksum(&self, ip_header: &[u8], tcp_segment: &[u8], payload: &[u8]) -> u16 {
        let mut pseudo_header = Vec::new();

        // 疑似ヘッダーの構築
        pseudo_header.extend_from_slice(&ip_header[12..20]); // 送信元と宛先IP
        pseudo_header.push(0); // ゼロパディング
        pseudo_header.push(6); // プロトコル (TCP = 6)
        pseudo_header.extend_from_slice(&((tcp_segment.len() + payload.len()) as u16).to_be_bytes());

        // TCPセグメントとペイロードを追加
        pseudo_header.extend_from_slice(tcp_segment);
        pseudo_header.extend_from_slice(payload);

        // パディングが必要な場合は0を追加
        if pseudo_header.len() % 2 != 0 {
            pseudo_header.push(0);
        }

        PacketInjector::calculate_checksum(&pseudo_header)
    }
}