use crate::network::packet::ethernet::EthernetHeader;
use crate::network::packet::{NetworkHeader, Packet, TransportHeader};
use crate::network::packet::ipv4::IPv4Header;
use crate::network::packet::tcp::TCPHeader;
use crate::network::packet::PacketMetadata;
use crate::core::error::TunnelResult;
use pnet::datalink::{self, Channel, NetworkInterface};

pub struct PacketCapture {
    interface: NetworkInterface,
    buffer_size: usize,
}

impl PacketCapture {
    pub fn new(interface: NetworkInterface, buffer_size: usize) -> Self {
        Self {
            interface,
            buffer_size,
        }
    }

    pub async fn next_packet(&self) -> TunnelResult<Packet> {
        let (_, mut rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(crate::core::error::TunnelError::Capture(
                std::io::Error::new(std::io::ErrorKind::Other, "未サポートのチャネルタイプです")
            )),
            Err(e) => return Err(crate::core::error::TunnelError::Capture(e)),
        };

        match rx.next() {
            Ok(packet) => {
                // パケットのパース処理を実装
                Ok(self.parse_packet(&packet)?)
            }
            Err(e) => Err(crate::core::error::TunnelError::Capture(e)),
        }
    }

    fn parse_packet(&self, data: &[u8]) -> TunnelResult<Packet> {
        let (ethernet_header, remainder) = EthernetHeader::parse(data)
            .ok_or_else(|| crate::core::error::TunnelError::Capture(
                std::io::Error::new(std::io::ErrorKind::Other, "イーサネットヘッダーのパースに失敗しました")
            ))?;

        // ネットワーク層のパース
        let (network_header, transport_data) = match ethernet_header.ethertype {
            0x0800 => {  // IPv4
                let (ipv4, remainder) = IPv4Header::parse(remainder)
                    .ok_or_else(|| crate::core::error::TunnelError::Capture(
                        std::io::Error::new(std::io::ErrorKind::Other, "IPv4ヘッダーのパースに失敗しました")
                    ))?;
                (NetworkHeader::IPv4(ipv4), remainder)
            }
            // 他のプロトコルのサポートを追加
            _ => return Err(crate::core::error::TunnelError::Capture(
                std::io::Error::new(std::io::ErrorKind::Other, "未サポートのプロトコルです")
            )),
        };

        // トランスポート層のパース
        let (transport_header, payload) = match &network_header {
            NetworkHeader::IPv4(ipv4) => {
                match ipv4.protocol {
                    6 => {  // TCP
                        let (tcp, remainder) = TCPHeader::parse(transport_data)
                            .ok_or_else(|| crate::core::error::TunnelError::Capture(
                                std::io::Error::new(std::io::ErrorKind::Other, "TCPヘッダーのパースに失敗しました")
                            ))?;
                        (Some(TransportHeader::TCP(tcp)), remainder)
                    }
                    // 他のプロトコルのサポートを追加
                    _ => (None, transport_data),
                }
            }
            // IPv6のサポートを追加
        };

        Ok(Packet {
            ethernet: ethernet_header,
            network: network_header,
            transport: transport_header,
            payload: payload.to_vec(),
            metadata: PacketMetadata {
                timestamp: chrono::Utc::now(),
                interface: self.interface.name.clone(),
                length: data.len(),
                is_incoming: true,
            },
        })
    }
}