use crate::select_device::select_device;
use dotenv::dotenv;
use pcap::{Active, Capture, Device};
mod select_device;
mod host_ids;
mod vpn;
mod real_time_analytics;
mod web_console;
mod database;

use crate::host_ids::packet_analysis::packet_analysis;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // .envファイルを読み込む
    dotenv().expect(".envファイルの読み取りに失敗しました");

    //let env = dotenv::var("ENV").expect("ENVの取得に失敗しました");

    let (cap, device): (Capture<Active>, Device) = select_device()?;
    println!("デバイスの選択に成功しました: {}", device.name);

    if let Err(e) = packet_analysis(cap) {
        println!("パケットの解析に失敗しました: {}", e);
    }

    Ok(())
}