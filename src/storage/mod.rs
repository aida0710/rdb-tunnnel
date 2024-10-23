use crate::storage::models::packet::StoredPacket;

pub mod models;
pub mod repository;
pub mod migrations;

impl StoredPacket {
    pub fn into_network_packet(&self) -> crate::network::packet::Packet {
        // This is a simplified conversion - you'll need to implement full conversion
        unimplemented!("Need to implement full packet conversion")
    }
}